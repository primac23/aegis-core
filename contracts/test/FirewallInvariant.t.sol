// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";

/// @notice Drives the firewall with random attestations and records, by construction,
///         whether each attempt carried a valid quorum. Ghost state feeds the invariants.
contract BridgeHandler is Test {
    IFirewallGatedBridge public immutable bridge;
    uint256 internal constant SET_ID = 1;
    uint256 internal constant N_MESSAGES = 20;
    uint256 internal constant SOURCE_BLOCK = 100;

    bytes[] internal messages;
    mapping(bytes32 => uint256) public successes;
    bool public unauthorizedRelease;
    bool public legitRejected;
    uint256 public successfulReleases;
    uint256 public rejectedAttempts;

    constructor(IFirewallGatedBridge _bridge) {
        bridge = _bridge;
        for (uint256 i = 0; i < N_MESSAGES; i++) {
            messages.push(abi.encode(address(uint160(0xA11CE + i)), (i + 1) * 1 ether, i, uint256(1111), address(0xB0B)));
        }
    }

    function messageCount() external view returns (uint256) {
        return messages.length;
    }

    function messageHash(uint256 i) external view returns (bytes32) {
        return keccak256(messages[i]);
    }

    // ------------------------------------------------------------------ fuzzed actions

    function warp(uint256 secondsForward) external {
        vm.warp(block.timestamp + bound(secondsForward, 0, 1 hours));
    }

    function attemptRelease(
        uint256 msgSeed,
        uint8 signerMask,
        uint8 setIdSeed,
        uint8 timeMode,
        bool tamperRoot,
        bool reverseOrder,
        bool emergency
    ) external {
        _attempt(msgSeed, signerMask, setIdSeed, timeMode, tamperRoot, reverseOrder, emergency);
    }

    /// @dev Always well-formed (guardians A+B, current set, valid window) so liveness is exercised often.
    function attemptValidRelease(uint256 msgSeed, bool emergency) external {
        _attempt(msgSeed, 0x03, 1, 0, false, false, emergency);
    }

    // ------------------------------------------------------------------ internals

    function _attempt(
        uint256 msgSeed,
        uint8 signerMask,
        uint8 setIdSeed,
        uint8 timeMode,
        bool tamperRoot,
        bool reverseOrder,
        bool emergency
    ) internal {
        bytes memory m = messages[msgSeed % N_MESSAGES];
        bytes32 mh = keccak256(m);
        uint256 setId = setIdSeed % 4 == 0 ? SET_ID + 1 : SET_ID;
        uint256 mode = timeMode % 4;
        (uint256 va, uint256 vu) = _window(mode);
        bytes32 root = keccak256(abi.encode("root", mh));
        bytes32 digest = bridge.hashTypedAttestation(mh, root, va, vu, SOURCE_BLOCK, setId);

        (Signature[] memory sigs, uint256 guardianSigs) = _sign(digest, signerMask, reverseOrder);
        bytes memory att = abi.encode(
            MultiAttestation(mh, tamperRoot ? keccak256("tampered") : root, va, vu, SOURCE_BLOCK, setId, sigs)
        );

        bool legit = !tamperRoot && setId == SET_ID && mode == 0 && guardianSigs >= 2
            && !(reverseOrder && sigs.length > 1) && successes[mh] == 0;

        bool ok;
        if (emergency) {
            try bridge.emergencyRelease(m, att) returns (bytes32) {
                ok = true;
            } catch {}
        } else {
            try bridge.release(m, att) returns (bytes32) {
                ok = true;
            } catch {}
        }

        if (ok) {
            successes[mh]++;
            successfulReleases++;
            if (!legit) unauthorizedRelease = true;
        } else {
            rejectedAttempts++;
            if (legit) legitRejected = true;
        }
    }

    function _window(uint256 mode) internal view returns (uint256 va, uint256 vu) {
        uint256 t = block.timestamp;
        if (mode == 0) return (t, t + 60); //            valid
        if (mode == 1) return (t + 30, t + 90); //       not yet valid
        if (mode == 2) return (t - 100, t - 1); //       expired
        return (t, t + 3 minutes); //                    exceeds MAX_ATTESTATION_AGE
    }

    function _sign(bytes32 digest, uint8 mask, bool reverseOrder)
        internal
        pure
        returns (Signature[] memory sigs, uint256 guardianSigs)
    {
        uint256[4] memory keys = [uint256(0x1111), 0x2222, 0x3333, 0x9999]; // index 3 = outsider
        uint256[] memory chosen = new uint256[](4);
        uint256 n;
        for (uint256 i = 0; i < 4; i++) {
            if ((uint256(mask) >> i) & 1 == 1) {
                chosen[n++] = keys[i];
                if (i < 3) guardianSigs++;
            }
        }
        for (uint256 i = 1; i < n; i++) {
            uint256 k = chosen[i];
            uint256 j = i;
            while (j > 0 && vm.addr(chosen[j - 1]) > vm.addr(k)) {
                chosen[j] = chosen[j - 1];
                j--;
            }
            chosen[j] = k;
        }
        sigs = new Signature[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 key = reverseOrder ? chosen[n - 1 - i] : chosen[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
            sigs[i] = Signature(v, r, s);
        }
    }
}

contract FirewallInvariantTest is Test {
    IFirewallGatedBridge internal bridge;
    BridgeHandler internal handler;

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory g = new address[](3);
        g[0] = vm.addr(0x1111);
        g[1] = vm.addr(0x2222);
        g[2] = vm.addr(0x3333);
        bridge = new IFirewallGatedBridge(g, 2, 1);
        handler = new BridgeHandler(bridge);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = BridgeHandler.attemptRelease.selector;
        selectors[1] = BridgeHandler.attemptValidRelease.selector;
        selectors[2] = BridgeHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// Safety: nothing is released without >= threshold guardian signatures over the exact digest,
    /// the current guardian set and a valid window.
    function invariant_NoReleaseWithoutValidQuorum() public view {
        assertFalse(handler.unauthorizedRelease(), "release without a valid quorum");
    }

    /// Liveness: a correctly formed quorum attestation for an unreleased message is never rejected.
    function invariant_ValidQuorumAlwaysAccepted() public view {
        assertFalse(handler.legitRejected(), "valid quorum attestation rejected");
    }

    function invariant_NoMessageReleasedTwice() public view {
        for (uint256 i = 0; i < handler.messageCount(); i++) {
            assertLe(handler.successes(handler.messageHash(i)), 1, "message released twice");
        }
    }

    function invariant_ReleasedFlagMatchesHistory() public view {
        for (uint256 i = 0; i < handler.messageCount(); i++) {
            bytes32 mh = handler.messageHash(i);
            assertEq(bridge.released(mh), handler.successes(mh) == 1, "released flag diverges from history");
        }
    }
}

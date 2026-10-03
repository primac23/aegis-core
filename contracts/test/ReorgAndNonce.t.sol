// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";
import {SourceDepositBox} from "../src/SourceDepositBox.sol";

contract ReorgAndNonceTest is Test {
    IFirewallGatedBridge internal bridge;
    SourceDepositBox internal box;
    address internal alice;

    uint256 internal constant KEY_A = 0x1111;
    uint256 internal constant KEY_B = 0x2222;
    uint256 internal constant KEY_C = 0x3333;
    uint256 internal constant KEY_OUTSIDER = 0x9999;
    uint256 internal constant SET_ID = 1;
    uint256 internal constant SRC_BLOCK = 100;
    bytes32 internal constant ROOT = keccak256("finalized_source_root");

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory g = new address[](3);
        g[0] = vm.addr(KEY_A);
        g[1] = vm.addr(KEY_B);
        g[2] = vm.addr(KEY_C);
        bridge = new IFirewallGatedBridge(g, 2, SET_ID);
        box = new SourceDepositBox();
        alice = makeAddr("alice");
    }

    // ------------------------------------------------------------------ helpers

    function _keys(uint256 a, uint256 b) internal pure returns (uint256[] memory k) {
        k = new uint256[](2);
        k[0] = a;
        k[1] = b;
    }

    function _msg(uint256 n) internal view returns (bytes memory) {
        return abi.encode(alice, 10 ether, n, uint256(1111), address(box));
    }

    function _attest(
        bytes memory message,
        bytes32 root,
        uint256 srcBlock,
        uint256 validAfter,
        uint256 validUntil,
        uint256[] memory keys,
        bool sortKeys
    ) internal view returns (bytes memory) {
        bytes32 mh = keccak256(message);
        bytes32 digest = bridge.hashTypedAttestation(mh, root, validAfter, validUntil, srcBlock, SET_ID);

        if (sortKeys) {
            for (uint256 i = 1; i < keys.length; i++) {
                uint256 k = keys[i];
                uint256 j = i;
                while (j > 0 && vm.addr(keys[j - 1]) > vm.addr(k)) {
                    keys[j] = keys[j - 1];
                    j--;
                }
                keys[j] = k;
            }
        }

        Signature[] memory sigs = new Signature[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            sigs[i] = Signature(v, r, s);
        }
        return abi.encode(MultiAttestation(mh, root, validAfter, validUntil, srcBlock, SET_ID, sigs));
    }

    function _valid(bytes memory message) internal view returns (bytes memory) {
        return _attest(message, ROOT, SRC_BLOCK, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_B), true);
    }

    // ------------------------------------------------------------------ nonce / uniqueness

    function test_SourceNonce_IdenticalDepositsHaveDistinctHashes() public {
        (bytes32 h1,) = box.deposit(alice, 10 ether);
        (bytes32 h2,) = box.deposit(alice, 10 ether);
        assertTrue(h1 != h2, "identical deposits must not collide");
        assertEq(box.nonce(), 2);
    }

    function test_IdenticalTransfers_BothReleasable() public {
        (, bytes memory p1) = box.deposit(alice, 10 ether);
        (, bytes memory p2) = box.deposit(alice, 10 ether);
        bridge.release(p1, _valid(p1));
        bridge.release(p2, _valid(p2));
        assertTrue(bridge.released(keccak256(p1)));
        assertTrue(bridge.released(keccak256(p2)));
    }

    // ------------------------------------------------------------------ reorg (documented limitation)

    /// @dev KNOWN LIMITATION: the destination has no view of canonical source state.
    ///      An attestation over a root that was later reorged out is accepted.
    ///      Reorg safety is enforced by the guardian finality policy (see scripts/live_reorg_demo.sh, scenario D).
    function test_KnownLimitation_OrphanedRootAttestationIsAccepted() public {
        bytes memory m = _msg(0);
        bytes32 orphanedRoot = keccak256("root_of_block_reorged_out");
        bridge.release(
            m, _attest(m, orphanedRoot, SRC_BLOCK, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_B), true)
        );
        assertTrue(bridge.released(keccak256(m)));
    }

    function test_RevertWhen_RootTamperedAfterSigning() public {
        bytes memory m = _msg(0);
        MultiAttestation memory a = abi.decode(_valid(m), (MultiAttestation));
        a.sourceStateRoot = keccak256("reorged_root");
        vm.expectRevert();
        bridge.release(m, abi.encode(a));
    }

    // ------------------------------------------------------------------ signer set

    function test_RevertWhen_DuplicateSigner() public {
        bytes memory m = _msg(0);
        bytes memory att = _attest(m, ROOT, SRC_BLOCK, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_A), true);
        vm.expectRevert(IFirewallGatedBridge.DuplicateSigner.selector);
        bridge.release(m, att);
    }

    function test_RevertWhen_SignersNotSortedAscending() public {
        bytes memory m = _msg(0);
        uint256[] memory desc = vm.addr(KEY_A) > vm.addr(KEY_B) ? _keys(KEY_A, KEY_B) : _keys(KEY_B, KEY_A);
        bytes memory att = _attest(m, ROOT, SRC_BLOCK, block.timestamp, block.timestamp + 60, desc, false);
        vm.expectRevert(IFirewallGatedBridge.DuplicateSigner.selector);
        bridge.release(m, att);
    }

    function test_RevertWhen_OutsiderSignatureDoesNotCountTowardQuorum() public {
        bytes memory m = _msg(0);
        bytes memory att =
            _attest(m, ROOT, SRC_BLOCK, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_OUTSIDER), true);
        vm.expectRevert(IFirewallGatedBridge.QuorumNotReached.selector);
        bridge.release(m, att);
    }

    // ------------------------------------------------------------------ validity window / fields

    function test_RevertWhen_AttestationNotYetValid() public {
        bytes memory m = _msg(0);
        bytes memory att =
            _attest(m, ROOT, SRC_BLOCK, block.timestamp + 10, block.timestamp + 60, _keys(KEY_A, KEY_B), true);
        vm.expectRevert(IFirewallGatedBridge.AttestationNotYetValid.selector);
        bridge.release(m, att);
    }

    function test_RevertWhen_ValidityWindowExceedsMaxAge() public {
        bytes memory m = _msg(0);
        bytes memory att =
            _attest(m, ROOT, SRC_BLOCK, block.timestamp, block.timestamp + 3 minutes, _keys(KEY_A, KEY_B), true);
        vm.expectRevert(IFirewallGatedBridge.AttestationInvalid.selector);
        bridge.release(m, att);
    }

    function test_RevertWhen_ZeroStateRoot() public {
        bytes memory m = _msg(0);
        bytes memory att =
            _attest(m, bytes32(0), SRC_BLOCK, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_B), true);
        vm.expectRevert(IFirewallGatedBridge.AttestationInvalid.selector);
        bridge.release(m, att);
    }

    function test_RevertWhen_ZeroSourceBlock() public {
        bytes memory m = _msg(0);
        bytes memory att = _attest(m, ROOT, 0, block.timestamp, block.timestamp + 60, _keys(KEY_A, KEY_B), true);
        vm.expectRevert(IFirewallGatedBridge.AttestationInvalid.selector);
        bridge.release(m, att);
    }

    // ------------------------------------------------------------------ cross-path replay

    function test_RevertWhen_EmergencyReplayAfterStandardRelease() public {
        bytes memory m = _msg(0);
        bridge.release(m, _valid(m));
        bytes memory att2 = _valid(m);
        vm.expectRevert(IFirewallGatedBridge.MessageAlreadyReleased.selector);
        bridge.emergencyRelease(m, att2);
    }
}

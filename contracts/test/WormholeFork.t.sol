// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WormholeAegisAdapter} from "../src/WormholeAegisAdapter.sol";
import {IWormhole} from "../src/interfaces/IWormhole.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";
import {RealVaaFixture} from "./fixtures/RealVaaFixture.sol";

/// @notice Runs against the deployed Wormhole Core on an Ethereum mainnet fork.
///         Enabled with AEGIS_FORK_TESTS=true (optional ETH_RPC_URL); skipped otherwise.
contract WormholeForkTest is Test, RealVaaFixture {
    uint256 internal constant KEY_A = 0x1111;
    uint256 internal constant KEY_B = 0x2222;
    uint256 internal constant KEY_C = 0x3333;
    uint256 internal constant SET_ID = 1;
    bytes32 internal constant ROOT = keccak256("finalized_source_root");

    bool internal forkEnabled;
    IWormhole internal core;
    WormholeAegisAdapter internal adapter;

    function setUp() public {
        forkEnabled = vm.envOr("AEGIS_FORK_TESTS", false);
        if (!forkEnabled) return;
        vm.createSelectFork(vm.envOr("ETH_RPC_URL", string("https://ethereum-rpc.publicnode.com")));
        core = IWormhole(address(bytes20(hex"98f3c9e6e3face36baad05fe09d375ef1464288b")));
        adapter = _deploy(REAL_EMITTER);
    }

    modifier onlyFork() {
        if (!forkEnabled) {
            vm.skip(true);
            return;
        }
        _;
    }

    function _deploy(bytes32 emitter) internal returns (WormholeAegisAdapter) {
        address[] memory g = new address[](3);
        g[0] = vm.addr(KEY_A);
        g[1] = vm.addr(KEY_B);
        g[2] = vm.addr(KEY_C);
        uint16[] memory chains = new uint16[](1);
        chains[0] = REAL_EMITTER_CHAIN;
        bytes32[] memory emitters = new bytes32[](1);
        emitters[0] = emitter;
        return new WormholeAegisAdapter(g, 2, SET_ID, address(core), chains, emitters);
    }

    function _aegis(bytes32 messageHash) internal view returns (bytes memory) {
        uint256 validUntil = block.timestamp + 60;
        bytes32 digest = adapter.hashTypedAttestation(messageHash, ROOT, block.timestamp, validUntil, 1, SET_ID);
        uint256 k1 = KEY_A;
        uint256 k2 = KEY_B;
        if (vm.addr(KEY_A) > vm.addr(KEY_B)) {
            k1 = KEY_B;
            k2 = KEY_A;
        }
        Signature[] memory sigs = new Signature[](2);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(k1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(k2, digest);
        sigs[0] = Signature(v1, r1, s1);
        sigs[1] = Signature(v2, r2, s2);
        return abi.encode(MultiAttestation(messageHash, ROOT, block.timestamp, validUntil, 1, SET_ID, sigs));
    }

    function test_Fork_RealVaa_VerifiedByDeployedWormholeCore() public onlyFork {
        (IWormhole.VM memory v, bool valid, string memory reason) = core.parseAndVerifyVM(REAL_VAA);
        assertTrue(valid, reason);
        assertEq(v.emitterChainId, REAL_EMITTER_CHAIN);
        assertEq(v.emitterAddress, REAL_EMITTER);
        assertTrue(v.hash != bytes32(0));
    }

    function test_Fork_RealVaa_AuthenticButStillRequiresAegis() public onlyFork {
        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        adapter.completeTransferWithAegis(REAL_VAA, "");
    }

    function test_Fork_TamperedRealVaa_RejectedByWormholeCore() public onlyFork {
        bytes memory t = REAL_VAA;
        t[t.length - 1] = bytes1(uint8(t[t.length - 1]) ^ 0x01);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.InvalidVaa.selector, "VM signature invalid"));
        adapter.completeTransferWithAegis(t, "");
    }

    function test_Fork_RealVaa_UnregisteredEmitterRejected() public onlyFork {
        WormholeAegisAdapter other = _deploy(bytes32(uint256(0xBAD)));
        vm.expectRevert(
            abi.encodeWithSelector(WormholeAegisAdapter.UnknownEmitter.selector, REAL_EMITTER_CHAIN, REAL_EMITTER)
        );
        other.completeTransferWithAegis(REAL_VAA, "");
    }

    function test_Fork_RealVaa_AegisBoundToDifferentHashRejected() public onlyFork {
        bytes memory att = _aegis(keccak256("not-this-vaa"));
        vm.expectRevert(IFirewallGatedBridge.InvalidMessage.selector);
        adapter.completeTransferWithAegis(REAL_VAA, att);
    }
}

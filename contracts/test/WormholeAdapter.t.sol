// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WormholeAegisAdapter} from "../src/WormholeAegisAdapter.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";
import {MockWormhole} from "./mocks/MockWormhole.sol";

contract WormholeAdapterTest is Test {
    WormholeAegisAdapter internal adapter;
    MockWormhole internal core;

    uint256 internal constant KEY_A = 0x1111;
    uint256 internal constant KEY_B = 0x2222;
    uint256 internal constant KEY_C = 0x3333;
    uint256 internal constant WH_GUARDIAN_KEY = 0x7777;
    uint256 internal constant FORGED_KEY = 0x6666;
    uint256 internal constant SET_ID = 1;
    uint16 internal constant SRC_CHAIN = 2;
    uint8 internal constant FINALIZED = 1;
    bytes32 internal constant EMITTER = bytes32(uint256(0xB0B));
    bytes32 internal constant ROOT = keccak256("wormhole_canonical_state");

    address internal alice;
    bytes internal payload;

    function setUp() public {
        vm.warp(1_000_000);
        alice = makeAddr("alice");
        payload = abi.encode(alice, 50 ether, uint256(0), uint256(SRC_CHAIN), address(0xB0B));
        core = new MockWormhole(vm.addr(WH_GUARDIAN_KEY));

        uint16[] memory chains = new uint16[](1);
        chains[0] = SRC_CHAIN;
        bytes32[] memory emitters = new bytes32[](1);
        emitters[0] = EMITTER;
        adapter = new WormholeAegisAdapter(_guardians(), 2, SET_ID, address(core), chains, emitters);
    }

    // ------------------------------------------------------------------ helpers

    function _guardians() internal pure returns (address[] memory g) {
        g = new address[](3);
        g[0] = vm.addr(KEY_A);
        g[1] = vm.addr(KEY_B);
        g[2] = vm.addr(KEY_C);
    }

    function _vaa(uint16 chain, bytes32 emitter, uint64 seq, uint8 consistency, uint256 signerKey)
        internal
        view
        returns (bytes memory encoded, bytes32 vaaHash)
    {
        bytes memory body =
            abi.encode(uint8(1), uint32(block.timestamp), uint32(0), chain, emitter, seq, consistency, payload);
        vaaHash = keccak256(abi.encodePacked(keccak256(body)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, vaaHash);
        encoded = abi.encode(body, v, r, s);
    }

    function _validVaa() internal view returns (bytes memory, bytes32) {
        return _vaa(SRC_CHAIN, EMITTER, 42, FINALIZED, WH_GUARDIAN_KEY);
    }

    function _aegis(bytes32 messageHash) internal view returns (bytes memory) {
        uint256 validUntil = block.timestamp + 60;
        bytes32 digest = adapter.hashTypedAttestation(messageHash, ROOT, block.timestamp, validUntil, 19_500_000, SET_ID);
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
        return abi.encode(MultiAttestation(messageHash, ROOT, block.timestamp, validUntil, 19_500_000, SET_ID, sigs));
    }

    // ------------------------------------------------------------------ happy path

    function test_SuccessWhen_VaaAndAegisQuorumValid() public {
        (bytes memory vaa, bytes32 h) = _validVaa();
        bytes memory att = _aegis(h);
        adapter.completeTransferWithAegis(vaa, att);
        assertTrue(adapter.released(h));
    }

    // ------------------------------------------------------------------ AEGIS authorization

    function test_RevertWhen_VaaAuthentic_ButAegisAuthorizationMissing() public {
        (bytes memory vaa,) = _validVaa();
        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        adapter.completeTransferWithAegis(vaa, "");
    }

    function test_RevertWhen_VaaMismatchedWithAegisMessageHash() public {
        (bytes memory vaa,) = _validVaa();
        (, bytes32 otherHash) = _vaa(SRC_CHAIN, EMITTER, 999, FINALIZED, WH_GUARDIAN_KEY);
        bytes memory att = _aegis(otherHash);
        vm.expectRevert(IFirewallGatedBridge.InvalidMessage.selector);
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_AttestationBoundToRawBytesInsteadOfVaaHash() public {
        (bytes memory vaa,) = _validVaa();
        bytes memory att = _aegis(keccak256(vaa));
        vm.expectRevert(IFirewallGatedBridge.InvalidMessage.selector);
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_VaaReplayed() public {
        (bytes memory vaa, bytes32 h) = _validVaa();
        bytes memory att = _aegis(h);
        adapter.completeTransferWithAegis(vaa, att);
        vm.expectRevert(IFirewallGatedBridge.MessageAlreadyReleased.selector);
        adapter.completeTransferWithAegis(vaa, att);
    }

    // ------------------------------------------------------------------ Wormhole authenticity

    function test_RevertWhen_VaaSignatureInvalid() public {
        (bytes memory vaa, bytes32 h) = _vaa(SRC_CHAIN, EMITTER, 42, FINALIZED, FORGED_KEY);
        bytes memory att = _aegis(h);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.InvalidVaa.selector, "VM signature invalid"));
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_UnknownEmitterChain() public {
        (bytes memory vaa, bytes32 h) = _vaa(5, EMITTER, 42, FINALIZED, WH_GUARDIAN_KEY);
        bytes memory att = _aegis(h);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.UnknownEmitter.selector, uint16(5), EMITTER));
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_SpoofedEmitterOnRegisteredChain() public {
        bytes32 spoofed = bytes32(uint256(0xBAD));
        (bytes memory vaa, bytes32 h) = _vaa(SRC_CHAIN, spoofed, 42, FINALIZED, WH_GUARDIAN_KEY);
        bytes memory att = _aegis(h);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.UnknownEmitter.selector, SRC_CHAIN, spoofed));
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_VaaNotFinalized_Instant() public {
        (bytes memory vaa, bytes32 h) = _vaa(SRC_CHAIN, EMITTER, 42, 200, WH_GUARDIAN_KEY);
        bytes memory att = _aegis(h);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.VaaNotFinalized.selector, uint8(200)));
        adapter.completeTransferWithAegis(vaa, att);
    }

    function test_RevertWhen_VaaNotFinalized_Safe() public {
        (bytes memory vaa, bytes32 h) = _vaa(SRC_CHAIN, EMITTER, 42, 201, WH_GUARDIAN_KEY);
        bytes memory att = _aegis(h);
        vm.expectRevert(abi.encodeWithSelector(WormholeAegisAdapter.VaaNotFinalized.selector, uint8(201)));
        adapter.completeTransferWithAegis(vaa, att);
    }

    // ------------------------------------------------------------------ constructor

    function test_RevertWhen_WormholeCoreIsZeroAddress() public {
        address[] memory g = _guardians();
        uint16[] memory chains = new uint16[](1);
        chains[0] = SRC_CHAIN;
        bytes32[] memory emitters = new bytes32[](1);
        emitters[0] = EMITTER;
        vm.expectRevert(WormholeAegisAdapter.InvalidWormholeCore.selector);
        new WormholeAegisAdapter(g, 2, SET_ID, address(0), chains, emitters);
    }

    function test_RevertWhen_EmitterConfigMismatch() public {
        address[] memory g = _guardians();
        uint16[] memory chains = new uint16[](2);
        bytes32[] memory emitters = new bytes32[](1);
        emitters[0] = EMITTER;
        vm.expectRevert(WormholeAegisAdapter.EmitterConfigMismatch.selector);
        new WormholeAegisAdapter(g, 2, SET_ID, address(core), chains, emitters);
    }
}

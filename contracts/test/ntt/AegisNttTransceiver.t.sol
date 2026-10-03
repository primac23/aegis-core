// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AegisNttTransceiver} from "../../src/ntt/AegisNttTransceiver.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../../src/IFirewallGatedBridge.sol";
import {TransceiverStructs, ITransceiverMinimal} from "../../src/ntt/INttInterfaces.sol";
import {MockNttManager} from "./MockNttManager.sol";

contract AegisNttTransceiverTest is Test {
    AegisNttTransceiver internal aegis;
    MockNttManager internal manager;

    uint256 internal constant KEY_A = 0x1111;
    uint256 internal constant KEY_B = 0x2222;
    uint256 internal constant KEY_C = 0x3333;
    uint256 internal constant OUTSIDER = 0x9999;
    uint256 internal constant SET_ID = 1;
    uint16 internal constant SRC_CHAIN = 2;
    bytes32 internal constant SRC_MANAGER = bytes32(uint256(0x5112E));
    bytes32 internal constant ROOT = keccak256("ntt_source_root");
    address internal token = address(0x7111);

    bytes internal nttMsg;
    bytes32 internal msgHash;

    function setUp() public {
        vm.warp(1_000_000);
        manager = new MockNttManager(token, 2); // 2/2: Wormhole + AEGIS
        aegis = new AegisNttTransceiver(address(manager), token, _guardians(), 2, SET_ID);
        manager.registerTransceiver(address(aegis), 1);
        manager.registerTransceiver(address(this), 2); // stands in for the Wormhole transceiver
        nttMsg = abi.encode(uint256(42), makeAddr("bob"), uint256(5 ether));
        msgHash = keccak256(nttMsg);
    }

    function _guardians() internal pure returns (address[] memory g) {
        g = new address[](3);
        g[0] = vm.addr(KEY_A);
        g[1] = vm.addr(KEY_B);
        g[2] = vm.addr(KEY_C);
    }

    function _attest(bytes32 h, uint256 k1, uint256 k2) internal view returns (bytes memory) {
        uint256 vu = block.timestamp + 60;
        bytes32 digest = aegis.hashTypedAttestation(h, ROOT, block.timestamp, vu, 100, SET_ID);
        if (vm.addr(k1) > vm.addr(k2)) (k1, k2) = (k2, k1);
        Signature[] memory sigs = new Signature[](2);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(k1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(k2, digest);
        sigs[0] = Signature(v1, r1, s1);
        sigs[1] = Signature(v2, r2, s2);
        return abi.encode(MultiAttestation(h, ROOT, block.timestamp, vu, 100, SET_ID, sigs));
    }

    function _wormholeAttest() internal {
        manager.attestationReceived(SRC_CHAIN, SRC_MANAGER, nttMsg); // this == transceiver #2
    }

    // --- identity ---

    function test_TransceiverType_IsAegis() public view {
        assertEq(aegis.getTransceiverType(), "aegis");
        assertEq(aegis.getNttManagerToken(), token);
        assertEq(aegis.quoteDeliveryPrice(SRC_CHAIN, TransceiverStructs.TransceiverInstruction(0, "")), 0);
    }

    // --- the core flow ---

    function test_AegisAttests_ThenThresholdMet_Executes() public {
        _wormholeAttest();
        assertEq(manager.attestations(msgHash), 1);
        assertFalse(manager.executed(msgHash));

        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, _attest(msgHash, KEY_A, KEY_B));
        assertEq(manager.attestations(msgHash), 2);
        assertTrue(manager.executed(msgHash), "2/2 threshold should execute");
    }

    function test_AegisAlone_DoesNotReachThreshold() public {
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, _attest(msgHash, KEY_A, KEY_B));
        assertEq(manager.attestations(msgHash), 1);
        assertFalse(manager.executed(msgHash), "AEGIS alone must not execute under 2/2");
    }

    function test_WormholeAlone_DoesNotReachThreshold() public {
        _wormholeAttest();
        assertEq(manager.attestations(msgHash), 1);
        assertFalse(manager.executed(msgHash), "Wormhole alone must not execute under 2/2");
    }

    // --- AEGIS gate rejects bad attestations before touching the manager ---

    function test_RevertWhen_NoQuorum_OneGuardianPlusOutsider() public {
        bytes memory att = _attest(msgHash, KEY_A, OUTSIDER);
        vm.expectRevert(IFirewallGatedBridge.QuorumNotReached.selector);
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, att);
        assertEq(manager.attestations(msgHash), 0);
    }

    function test_RevertWhen_AttestationMissing() public {
        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, "");
    }

    function test_RevertWhen_AttestationBoundToDifferentMessage() public {
        bytes memory att = _attest(keccak256("other"), KEY_A, KEY_B);
        vm.expectRevert(IFirewallGatedBridge.InvalidMessage.selector);
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, att);
    }

    function test_RevertWhen_AegisReplayed() public {
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, _attest(msgHash, KEY_A, KEY_B));
        bytes memory att2 = _attest(msgHash, KEY_A, KEY_B);
        vm.expectRevert(IFirewallGatedBridge.MessageAlreadyReleased.selector);
        aegis.receiveAndAttest(SRC_CHAIN, SRC_MANAGER, nttMsg, att2);
    }

    // --- access control ---

    function test_RevertWhen_SendMessageCallerNotManager() public {
        vm.expectRevert(abi.encodeWithSelector(ITransceiverMinimal.CallerNotNttManager.selector, address(this)));
        aegis.sendMessage(SRC_CHAIN, TransceiverStructs.TransceiverInstruction(0, ""), nttMsg, bytes32(0), bytes32(0));
    }

    function test_SendMessage_FromManager_IsNoOp() public {
        vm.prank(address(manager));
        aegis.sendMessage(SRC_CHAIN, TransceiverStructs.TransceiverInstruction(0, ""), nttMsg, bytes32(0), bytes32(0));
    }

    function test_RevertWhen_ConstructedWithZeroManager() public {
        vm.expectRevert(AegisNttTransceiver.ZeroManager.selector);
        new AegisNttTransceiver(address(0), token, _guardians(), 2, SET_ID);
    }
}

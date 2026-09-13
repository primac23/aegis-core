// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";

contract FirewallBridgeSecurityMatrixTest is Test {
    IFirewallGatedBridge public bridge;

    uint256 internal keyA = 0x1111;
    uint256 internal keyB = 0x2222;
    uint256 internal keyC = 0x3333;
    uint256 internal keyAttacker = 0x9999;

    address internal guardianA;
    address internal guardianB;
    address internal guardianC;
    address internal attacker;

    uint256 internal activeSetId = 1;
    bytes32 internal stateRoot = keccak256("canonical_state_root");
    bytes internal sampleMessage;
    bytes32 internal sampleHash;

    function setUp() public {
        vm.warp(1_000_000); // Evită underflow pe block.timestamp

        guardianA = vm.addr(keyA);
        guardianB = vm.addr(keyB);
        guardianC = vm.addr(keyC);
        attacker = vm.addr(keyAttacker);

        address[] memory guardians = new address[](3);
        guardians[0] = guardianA;
        guardians[1] = guardianB;
        guardians[2] = guardianC;

        bridge = new IFirewallGatedBridge(guardians, 2, activeSetId);
        sampleMessage = abi.encode(makeAddr("alice"), 100 ether);
        sampleHash = keccak256(sampleMessage);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (Signature memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return Signature(v, r, s);
    }

    function test_SecurityMatrix_01_SingleGuardian_Blocked() public {
        bytes32 digest = bridge.hashTypedAttestation(sampleHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000, activeSetId);
        Signature[] memory sigs = new Signature[](1);
        sigs[0] = _sign(keyA, digest);

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: sampleHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        vm.expectRevert(IFirewallGatedBridge.QuorumNotReached.selector);
        bridge.release(sampleMessage, attestation);
    }

    function test_SecurityMatrix_02_QuorumTwoOfThree_Allowed() public {
        bytes32 digest = bridge.hashTypedAttestation(sampleHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000, activeSetId);
        Signature[] memory sigs = new Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = _sign(keyA, digest);
            sigs[1] = _sign(keyB, digest);
        } else {
            sigs[0] = _sign(keyB, digest);
            sigs[1] = _sign(keyA, digest);
        }

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: sampleHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        bridge.release(sampleMessage, attestation);
        assertTrue(bridge.released(sampleHash));
    }

    function test_SecurityMatrix_03_StaleGuardianSet_Blocked() public {
        bytes32 digest = bridge.hashTypedAttestation(sampleHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000, 0);
        Signature[] memory sigs = new Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = _sign(keyA, digest);
            sigs[1] = _sign(keyB, digest);
        } else {
            sigs[0] = _sign(keyB, digest);
            sigs[1] = _sign(keyA, digest);
        }

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: sampleHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: 0,
                signatures: sigs
            })
        );

        vm.expectRevert(IFirewallGatedBridge.InvalidGuardianSet.selector);
        bridge.release(sampleMessage, attestation);
    }

    function test_SecurityMatrix_04_ExpiredAttestation_Blocked() public {
        bytes32 digest = bridge.hashTypedAttestation(sampleHash, stateRoot, block.timestamp - 100, block.timestamp - 10, 19500000, activeSetId);
        Signature[] memory sigs = new Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = _sign(keyA, digest);
            sigs[1] = _sign(keyB, digest);
        } else {
            sigs[0] = _sign(keyB, digest);
            sigs[1] = _sign(keyA, digest);
        }

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: sampleHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp - 100,
                validUntil: block.timestamp - 10,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        vm.expectRevert(IFirewallGatedBridge.AttestationExpired.selector);
        bridge.release(sampleMessage, attestation);
    }

    function test_SecurityMatrix_05_EmergencyExit_RequiresAttestation() public {
        bytes memory emptyAttestation = "";
        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        bridge.emergencyRelease(sampleMessage, emptyAttestation);
    }

    function test_SecurityMatrix_06_EmergencyExit_AllowedWithAttestation() public {
        bytes32 digest = bridge.hashTypedAttestation(sampleHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000, activeSetId);
        Signature[] memory sigs = new Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = _sign(keyA, digest);
            sigs[1] = _sign(keyB, digest);
        } else {
            sigs[0] = _sign(keyB, digest);
            sigs[1] = _sign(keyA, digest);
        }

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: sampleHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        bridge.emergencyRelease(sampleMessage, attestation);
        assertTrue(bridge.released(sampleHash));
    }
}

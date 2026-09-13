// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract FirewallBridgeTest is Test {
    IFirewallGatedBridge public bridge;

    uint256 internal keyA = 0x1111;
    uint256 internal keyB = 0x2222;
    uint256 internal keyC = 0x3333;
    uint256 internal keyAttacker = 0x9999;

    address internal guardianA;
    address internal guardianB;
    address internal guardianC;
    address internal attacker;

    function setUp() public {
        guardianA = vm.addr(keyA);
        guardianB = vm.addr(keyB);
        guardianC = vm.addr(keyC);
        attacker = vm.addr(keyAttacker);

        // Sortăm adresele pentru test
        address[] memory guardians = new address[](3);
        guardians[0] = guardianA;
        guardians[1] = guardianB;
        guardians[2] = guardianC;

        // Prag 2 din 3
        bridge = new IFirewallGatedBridge(guardians, 2);
    }

    function test_RevertWhen_QuorumNotReached_SingleSignature() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);
        bytes32 stateRoot = keccak256("state_root_19500000");

        bytes32 digest = bridge.hashTypedAttestation(messageHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyA, digest);

        IFirewallGatedBridge.Signature[] memory sigs = new IFirewallGatedBridge.Signature[](1);
        sigs[0] = IFirewallGatedBridge.Signature(v, r, s);

        bytes memory attestation = abi.encode(
            IFirewallGatedBridge.MultiAttestation({
                messageHash: messageHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                signatures: sigs
            })
        );

        vm.expectRevert(IFirewallGatedBridge.QuorumNotReached.selector);
        bridge.release(message, attestation);
    }

    function test_Success_WhenQuorumReached_TwoOfThree() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);
        bytes32 stateRoot = keccak256("state_root_19500000");

        bytes32 digest = bridge.hashTypedAttestation(messageHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000);
        
        // Semnează gardianul A și B
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, digest);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, digest);

        // Sortare signeri pentru validarea din contract
        IFirewallGatedBridge.Signature[] memory sigs = new IFirewallGatedBridge.Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = IFirewallGatedBridge.Signature(vA, rA, sA);
            sigs[1] = IFirewallGatedBridge.Signature(vB, rB, sB);
        } else {
            sigs[0] = IFirewallGatedBridge.Signature(vB, rB, sB);
            sigs[1] = IFirewallGatedBridge.Signature(vA, rA, sA);
        }

        bytes memory attestation = abi.encode(
            IFirewallGatedBridge.MultiAttestation({
                messageHash: messageHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                signatures: sigs
            })
        );

        bridge.release(message, attestation);
        assertTrue(bridge.released(messageHash));
    }
}

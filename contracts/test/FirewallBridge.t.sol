// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract FirewallBridgeTest is Test {
    IFirewallGatedBridge public bridge;

    uint256 internal keyA = 0x1111;
    uint256 internal keyB = 0x2222;
    uint256 internal keyC = 0x3333;

    address internal guardianA;
    address internal guardianB;
    address internal guardianC;

    uint256 internal activeSetId = 1;

    function setUp() public {
        guardianA = vm.addr(keyA);
        guardianB = vm.addr(keyB);
        guardianC = vm.addr(keyC);

        address[] memory guardians = new address[](3);
        guardians[0] = guardianA;
        guardians[1] = guardianB;
        guardians[2] = guardianC;

        // Prag 2 din 3, GuardianSetId = 1
        bridge = new IFirewallGatedBridge(guardians, 2, activeSetId);
    }

    function test_RevertWhen_StaleGuardianSet() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);
        bytes32 stateRoot = keccak256("state_root_19500000");

        bytes32 digest = bridge.hashTypedAttestation(messageHash, stateRoot, block.timestamp, block.timestamp + 60, 19500000, 0);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, digest);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, digest);

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
                guardianSetId: 0,
                signatures: sigs
            })
        );

        vm.expectRevert(IFirewallGatedBridge.InvalidGuardianSet.selector);
        bridge.release(message, attestation);
    }

    function test_RevertWhen_EquivocationSplitQuorum() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);
        
        bytes32 rootCanonical = keccak256("canonical_root");
        bytes32 rootFork = keccak256("fork_root");

        // Gardianul A semnează pe o stare de fork
        bytes32 digestFork = bridge.hashTypedAttestation(messageHash, rootFork, block.timestamp, block.timestamp + 60, 19500000, activeSetId);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, digestFork);

        // Doar semnătura lui A trimisă pentru starea canonicală (fără cvorum)
        IFirewallGatedBridge.Signature[] memory sigs = new IFirewallGatedBridge.Signature[](1);
        sigs[0] = IFirewallGatedBridge.Signature(vA, rA, sA);

        bytes memory attestation = abi.encode(
            IFirewallGatedBridge.MultiAttestation({
                messageHash: messageHash,
                sourceStateRoot: rootCanonical,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        // Revert garantat: 1 semnătură trimisă când sunt necesare 2
        vm.expectRevert(IFirewallGatedBridge.QuorumNotReached.selector);
        bridge.release(message, attestation);
    }
}

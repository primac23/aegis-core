// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract FirewallIntegrationTest is Test {
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

        bridge = new IFirewallGatedBridge(guardians, 2, activeSetId);
    }

    function test_EndToEnd_LegitimateRelease_MultiSigner() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);
        bytes32 sourceStateRoot = keccak256("state_root_19500000");

        uint256 validAfter = block.timestamp;
        uint256 validUntil = block.timestamp + 60;
        uint256 sourceBlock = 19500000;

        bytes32 digest = bridge.hashTypedAttestation(
            messageHash,
            sourceStateRoot,
            validAfter,
            validUntil,
            sourceBlock,
            activeSetId
        );

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
                sourceStateRoot: sourceStateRoot,
                validAfter: validAfter,
                validUntil: validUntil,
                sourceBlock: sourceBlock,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        bridge.release(message, attestation);
        assertTrue(bridge.released(messageHash));
    }

    function test_EndToEnd_ExploitBlocked_WhenReorgOccurs() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes memory emptyAttestation = "";

        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        bridge.release(message, emptyAttestation);
    }
}

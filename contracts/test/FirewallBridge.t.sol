// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract FirewallBridgeTest is Test {
    IFirewallGatedBridge public bridge;

    uint256 internal firewallPrivateKey = 0xA11CE;
    address internal firewallSigner;

    uint256 internal attackerPrivateKey = 0xB0B;
    address internal attacker;

    function setUp() public {
        firewallSigner = vm.addr(firewallPrivateKey);
        attacker = vm.addr(attackerPrivateKey);
        bridge = new IFirewallGatedBridge(firewallSigner);
    }

    function test_RevertWhen_AttestationMissing() public {
        bytes memory dummyMessage = abi.encode("transfer(100 ETH)");
        bytes memory emptyAttestation = "";

        vm.prank(attacker);
        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        bridge.release(dummyMessage, emptyAttestation);
    }

    function test_RevertWhen_SignerIsAttacker() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);

        uint256 validAfter = block.timestamp;
        uint256 validUntil = block.timestamp + 60;
        uint256 sourceBlock = 1000;

        bytes32 digest = bridge.hashTypedAttestation(messageHash, validAfter, validUntil, sourceBlock);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPrivateKey, digest);

        bytes memory badAttestation = abi.encode(
            IFirewallGatedBridge.Attestation({
                messageHash: messageHash,
                validAfter: validAfter,
                validUntil: validUntil,
                sourceBlock: sourceBlock,
                v: v,
                r: r,
                s: s
            })
        );

        vm.prank(attacker);
        vm.expectRevert(IFirewallGatedBridge.InvalidSigner.selector);
        bridge.release(message, badAttestation);
    }

    function test_SuccessfulRelease_WithValidAttestation() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);

        uint256 validAfter = block.timestamp;
        uint256 validUntil = block.timestamp + 60;
        uint256 sourceBlock = 1000;

        bytes32 digest = bridge.hashTypedAttestation(messageHash, validAfter, validUntil, sourceBlock);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(firewallPrivateKey, digest);

        bytes memory validAttestation = abi.encode(
            IFirewallGatedBridge.Attestation({
                messageHash: messageHash,
                validAfter: validAfter,
                validUntil: validUntil,
                sourceBlock: sourceBlock,
                v: v,
                r: r,
                s: s
            })
        );

        bridge.release(message, validAttestation);
        assertTrue(bridge.released(messageHash));
    }
}

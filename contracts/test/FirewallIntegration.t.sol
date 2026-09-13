// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract FirewallIntegrationTest is Test {
    IFirewallGatedBridge public bridge;

    // Cheia privată a firewall-ului (0xA11CE din Rust)
    uint256 internal firewallPrivateKey = 0xA11CE;
    address internal firewallSigner;

    function setUp() public {
        firewallSigner = vm.addr(firewallPrivateKey);
        bridge = new IFirewallGatedBridge(firewallSigner);
    }

    function test_EndToEnd_LegitimateRelease() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        bytes32 messageHash = keccak256(message);

        uint256 validAfter = block.timestamp;
        uint256 validUntil = block.timestamp + 60;
        uint256 sourceBlock = 19500000;

        // Calcul digest identic cu compute_digest() din Rust
        bytes32 digest = bridge.hashTypedAttestation(
            messageHash,
            validAfter,
            validUntil,
            sourceBlock
        );

        // Semnăm cu cheia firewall-ului
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(firewallPrivateKey, digest);

        bytes memory attestation = abi.encode(
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

        // Execuția reușește
        bridge.release(message, attestation);
        assertTrue(bridge.released(messageHash));
    }

    function test_EndToEnd_ExploitBlocked_WhenReorgOccurs() public {
        bytes memory message = abi.encode("transfer(100 ETH)");
        
        // În caz de reorg, motorul Rust dă FREEZE și refuză să emită semnătura.
        // Atacatorul încearcă să trimită apelul fără semnătură validă.
        bytes memory emptyAttestation = "";

        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        bridge.release(message, emptyAttestation);
    }
}

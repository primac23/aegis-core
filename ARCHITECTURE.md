# AEGIS Architectural Specification & Integration Guide

## 1. System Topology
* Chain A (Source): Emițător eveniment depozit (mesaj, block, state root).
* AEGIS Off-Chain Core: Monitorizare RPC, construire DAG cauzal, verificare cvorum M-of-N (2/3).
* Chain B (Destination): IFirewallGatedBridge validează atestarea EIP-712 prin modifier-ul checkFirewall.

## 2. Integration Primitive
Orice bridge partener integrează AEGIS prin moștenirea modifier-ului pe toate funcțiile cu impact economic:

```solidity
import {IFirewallGatedBridge} from "./IFirewallGatedBridge.sol";

contract PartnerBridge is IFirewallGatedBridge {
    function release(bytes calldata msgPayload, bytes calldata attestation)
        external
        checkFirewall(msgPayload, attestation)
    {
        // Business logic bridge existent
    }

    function emergencyRelease(bytes calldata msgPayload, bytes calldata attestation)
        external
        checkFirewall(msgPayload, attestation)
    {
        // Căile de urgență sunt protejate obligatoriu
    }
}
```

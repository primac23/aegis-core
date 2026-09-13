# AEGIS: Cross-Chain Release Authorization Firewall

**Problem:** Cross-chain bridges observe invalid or reorged economic states before reactive pause mechanisms (pause()) can execute through mempools, exposing protocols to MEV frontrunning and catastrophic asset drainage.

**Solution:** Fail-Closed authorization primitive. No valid cryptographic attestation implies no asset release.

---

## Key Security Properties (Specified Key Security Properties (Formally Verified in Suite) Validated via Foundry Suite)
* **Threshold Quorum (M-of-N):** 2/3 independent guardian signatures required.
* **Cryptographic State Binding:** Bound to sourceStateRoot, not just block height.
* **Epoch Protection:** Bound to immutable guardianSetId.
* **Universal Exit Gate:** Applied to both standard and emergency release paths.
* **Causal Invalidation:** Instant Freeze upon source-chain reorg.

---

## Quickstart & Reproducible Demo

### 1. Run Complete Foundry Security Matrix (10 Tests)
```bash
cd contracts && forge test -v
```

### 2. Run End-to-End Dual-Chain Adversarial Demo
```bash
./scripts/demo_adversarial_flow.sh
```

---

## Documentation
* [Pilot Specification & Rollout Plan](PILOT_PROPOSAL.md)
* [Threat Model & Security Invariants](THREAT_MODEL.md)
* [Architecture & Integration Adapter](ARCHITECTURE.md)

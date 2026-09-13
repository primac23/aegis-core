# AEGIS: Causal Invariant Cross-Chain Firewall

AEGIS is a low-latency, fail-closed security infrastructure for cross-chain bridges and liquidity transfer protocols.

## The Structural Flaw in Modern Bridges
Most cross-chain bridges rely on optimistic assumptions or mempool-based emergency pause functions. During source-chain reorganizations or deep invalidations, attackers leverage MEV / priority fees to execute unbacked releases before emergency transactions can be included.

## The AEGIS Architecture
AEGIS replaces reactive pausing with an **EIP-712 Fail-Closed Attestation Model**:
1. **Zero-Trust Release:** Target chain contracts (`IFirewallGatedBridge.sol`) require a cryptographically authenticated attestation bound to a specific source block and causal execution state.
2. **Sub-Millisecond Graph Traversal:** The off-chain engine maintains an in-memory incremental causal directed acyclic graph (DAG) in Rust, mapping state dependencies: `ChainState -> Message -> Release`.
3. **Instant Contamination Isolation:** Upon detecting a source-chain reorg or invariant deviation, invalidation propagates downstream in under 1ms, returning `Decision::Freeze` and refusing attestation signatures.

## Verification & Benchmarks
- **EVM Verification Gas:** ~29,368 gas on receipt
- **Graph Traversal Latency:** < 500 microseconds
- **Failure Mode:** Deterministic EVM revert on missing or expired attestation

## Reproduction Steps
```bash
# Contracts (Foundry)
cd contracts && forge test

# Live RPC Engine (Rust)
cd engine && cargo run --release
```

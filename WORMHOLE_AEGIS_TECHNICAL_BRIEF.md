# AEGIS Defense-in-Depth Authorization Layer for Wormhole Integrations

## 1. Problem Statement
Cross-chain message authentication proves that a source-chain event occurred. It does not cryptographically guarantee that the downstream economic execution remains valid if:
1. The source state undergoes a block reorganization after VAA issuance under lower consistency levels.
2. The economic derivation of the destination release becomes stale or invalidated.
3. Reactive pause transactions (pause()) lose mempool/MEV priority races.

## 2. Complementary Security Boundary
AEGIS does not replace Wormhole Guardians (13/19) or compete with the Global Accountant. It operates at an independent boundary:

* **Wormhole Core Contract:** Verifies message authenticity ("Was this message attested by the Guardian Network?").
* **AEGIS Adapter:** Verifies downstream causal validity ("Is this economic release still authorized under current source state commitments?").

```
                 WORMHOLE
                     │
               Guardian VAA
                     │
                     ▼
            ┌────────────────┐
            │ Wormhole Core  │ (Authenticity Verified)
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │ AEGIS Adapter  │ (Causal / Invariant Check)
            └───────┬────────┘
                    │
          ┌─────────┴─────────┐
          │                   │
     State Valid         State Invalid / Reorg
          │                   │
     Quorum >= M           FREEZE
          │                   │
          ▼                   X
       RELEASE             REVERT
```

## 3. Verified Security Invariants
* **Authorization Decoupling:** VAA.isValid does not imply Release.isAuthorized.
* **State Binding:** Attestation is bound to sourceStateRoot, preventing blind execution.
* **Epoch Binding:** Bound to guardianSetId, preventing cross-epoch replays.
* **Cross-Domain Integrity:** Attestation hash must strictly match the VAA payload hash (InvalidMessage revert on mismatch).

## 4. Proposed Pilot Scope
* **Mode:** Shadow Mode deployment (zero custody, non-blocking monitoring on testnet).
* **Metrics:** Detection latency, quorum availability, reorg reaction window.
* **Integration Surface:** WormholeAegisAdapter.completeTransferWithAegis(...).

## 5. Local Reproduction
```bash
cd contracts && forge test -v
./scripts/demo_adversarial_flow.sh
```

## 6. Implementation Status (v0.1.1)

- `WormholeAegisAdapter.completeTransferWithAegis` enforces the AEGIS quorum, message binding and replay protection. It does **not yet** call Wormhole Core `parseAndVerifyVM`; VAA verification is the next integration step.
- Reorg safety is enforced by the guardian finality policy, not on-chain. See `THREAT_MODEL.md` (Addendum v0.1.1) and `scripts/live_reorg_demo.sh`.
- Test suite: 23 Foundry tests, all passing (`cd contracts && forge test -vv`).

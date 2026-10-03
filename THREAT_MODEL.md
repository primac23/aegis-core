# AEGIS Threat Model & Security Invariants

## 1. System Invariants

### Invariant 1: Authorization Safety
$$\text{FirewallAuthorization}(P) \implies \text{Valid}(\text{msgHash}) \land \text{Valid}(\text{sourceStateRoot}) \land \text{Valid}(\text{guardianSetId}) \land \text{Valid}(\Delta t) \land (\text{Quorum} \ge M)$$

### Invariant 2: Release Safety
$$\forall \text{asset} \in \text{TransferredAssets}, \quad \text{Release}(\text{asset}) \implies \text{FirewallAuthorization}(\text{release})$$

### Invariant 3: Universal Economic Exit Coverage
$$\forall P \in \text{EconomicExitPaths}, \quad P \vdash \text{AegisFirewallGate}$$

### Invariant 4: Reorg Safety
$$\text{CanonicalStateInvalidated} \implies \neg \text{FirewallAuthorization}(\text{derivedRelease})$$

---

## 2. In-Scope Adversarial Protections (Guaranteed by AEGIS)
* **Zero Attestation Submissions**: Respingere imediată în EVM fără competiție în mempool.
* **Mempool Frontrunning & MEV Reordering**: Niciun builder nu poate ordona tranzacții pentru a produce fonduri dacă semnătura lipsește.
* **Source Chain Reorgs & Orphan Blocks**: Traversarea cauzală în DAG trece pe `Decision::Freeze` înainte ca o stare invalidată să obțină semnătură.
* **Byzantine / Equivocating Guardians (< M)**: Compromiterea a 1 gardian dintr-un set 2/3 nu poate autoriza retrageri; divizarea semnăturilor pe fork-uri dă revert.
* **Stale Epoch / Rotation Replays**: Semnăturile emise pe epoci vechi sunt respinse deterministic prin legarea de `guardianSetId`.
* **State Commitment Spoofing**: Includerea obligatorie a `sourceStateRoot` în digest-ul EIP-712 împiedică semnarea oarbă pe număr de bloc.

---

## 3. Out-of-Scope (Explicit Trust Boundaries)
* **Compromiterea simultană a >= M gardieni**: Dacă cvorumul este capturat integral (2/3), granița de securitate este încălcată.
* **Compromiterea consensului L1/L2 de destinație**: Atacuri de tip 51% pe lanțul de destinație.
* **Căi de ieșire nelegate la Gate**: Vulnerabilități în smart contracte terțe ale bridge-ului care nu moștenesc `AegisFirewallGate`.

---

## Addendum v0.1.1 — Reorg Safety & Guardian Finality Policy

**Trust boundary.** The destination contract verifies *who* signed and *what* they signed, not whether the attested source state is still canonical. An attestation over an orphaned `sourceStateRoot` is accepted on-chain (`test_KnownLimitation_OrphanedRootAttestationIsAccepted`).

**Mitigation.** Guardians MUST sign only when (1) the deposit has at least K confirmations and (2) the deposit receipt's block hash equals the canonical block hash at that height. Demonstrated live in `scripts/live_reorg_demo.sh`: naive guardians (scenario C) pay out an orphaned deposit; finality-aware guardians (scenario D) refuse to sign and the release fails closed.

**Residual risk.** A colluding or compromised quorum (≥ threshold keys) can authorize any release. K must be chosen per source chain according to its finality model.

## Addendum v0.2.0 — Wormhole Layer & Guardian Daemon

- **Wormhole:** a release requires a valid VAA (`parseAndVerifyVM`), the registered emitter for its source chain and a finalized consistency level. Non-finalized VAAs (200 instant, 201 safe) are rejected on-chain, closing the low-consistency reorg window for Wormhole-originated messages.
- **Guardian daemon:** implements the finality policy of Addendum v0.1.1 in Rust. Key custody is local (environment variable); HSM/MPC is a deployment requirement.
- **Liveness:** fewer than threshold guardians online means no attestation and therefore no release. This is fail-closed by design and is demonstrated in `scripts/live_daemon_demo.sh` (scenario E).

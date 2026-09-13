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

# AEGIS: Cross-Chain Release Authorization Firewall

**Problem:** Message authentication proves that a source-chain event occurred. It does not prove that the downstream economic release is still valid: a source reorg can orphan the deposit after the message is observed, and reactive `pause()` transactions can lose mempool/MEV races against an in-flight exploit.

**Solution:** A fail-closed authorization layer at the settlement boundary. An asset is released only with a valid M-of-N guardian attestation, on both the standard and emergency paths. No attestation, no release.

## How It Works

1. A deposit on the source chain emits a unique payload: `(recipient, amount, nonce, sourceChainId, sourceContract)`.
2. Guardians wait for source finality (K confirmations) and verify the deposit transaction is still canonical.
3. Guardians sign an EIP-712 attestation over `(messageHash, sourceStateRoot, validAfter, validUntil, sourceBlock, guardianSetId)`.
4. The destination verifies quorum, signer ordering, guardian set, validity window and message binding, marks the message released, then executes.

## Security Properties — 23 Foundry tests, all passing

| Property | Enforcement | Tests |
|---|---|---|
| Threshold quorum (2-of-3) | `QuorumNotReached` | `SecurityMatrix_01`, `SecurityMatrix_02`, `OutsiderSignatureDoesNotCountTowardQuorum` |
| Signer uniqueness & ordering | `DuplicateSigner` | `DuplicateSigner`, `SignersNotSortedAscending` |
| Epoch binding | `InvalidGuardianSet` | `SecurityMatrix_03_StaleGuardianSet_Blocked` |
| Bounded validity window | `AttestationExpired`, `AttestationNotYetValid`, `AttestationInvalid` | `SecurityMatrix_04`, `AttestationNotYetValid`, `ValidityWindowExceedsMaxAge` |
| Attested field integrity | EIP-712 digest, `AttestationInvalid` | `RootTamperedAfterSigning`, `ZeroStateRoot`, `ZeroSourceBlock` |
| Replay protection (both paths) | `MessageAlreadyReleased` | `EmergencyReplayAfterStandardRelease` |
| Per-deposit uniqueness | Source nonce in payload | `SourceNonce_IdenticalDepositsHaveDistinctHashes`, `IdenticalTransfers_BothReleasable` |
| Universal exit gate | Emergency path uses the same verifier | `SecurityMatrix_05`, `SecurityMatrix_06` |
| Fail-closed release | `AttestationMissing` | `EndToEnd_ReleaseBlocked_WhenAttestationMissing`, `VaaAuthentic_ButAegisAuthorizationMissing` |
| Cross-domain message binding | `InvalidMessage` | `VaaMismatchedWithAegisMessageHash` |
| **Known limitation** (documented) | — | `KnownLimitation_OrphanedRootAttestationIsAccepted` |

## Reorg Safety Model

The destination contract has no view of canonical source state, so it cannot detect that an attested `sourceStateRoot` was later reorged out. **Reorg safety is enforced by the guardian finality policy:** guardians sign only after K confirmations and only if the deposit transaction is still in the canonical chain.

`scripts/live_reorg_demo.sh` demonstrates this on two live Anvil chains with real EIP-712 signatures and real source reorgs:

| Scenario | Result |
|---|---|
| A. Legitimate transfer after K confirmations | Released |
| B. Replay of the same attestation | `MessageAlreadyReleased` |
| C. Reorg, naive guardians signing at 0 confirmations | **Released — orphaned deposit paid out (expected gap)** |
| D. Reorg, finality-aware guardians | Guardians refuse to sign → `AttestationMissing` |
| E. Second identical legitimate transfer | Released (unique nonce) |

## Scope & Known Limitations (v0.1.1)

- No on-chain light client or state proof; source validity is attested by the guardian quorum.
- `WormholeAegisAdapter` is an integration-surface prototype: it does not yet call Wormhole Core to verify the VAA. VAA authenticity is assumed to be verified upstream.
- The guardian set is fixed per deployment; rotation requires redeployment.
- The finality policy is implemented in the demo harness; the production guardian daemon (`engine/`) is in progress.
- No invariant fuzzing or formal verification yet. Verification cost scales with the number of signatures (O(M)).

## Quickstart

Requires [Foundry](https://getfoundry.sh) (`forge`, `anvil`, `cast`).

```bash
cd contracts && forge test -vv          # 23 tests
./scripts/live_reorg_demo.sh            # live dual-chain reorg demo (A–E)
```

## Documentation

- [Pilot Specification & Rollout Plan](PILOT_PROPOSAL.md)
- [Threat Model & Security Invariants](THREAT_MODEL.md)
- [Architecture & Integration Adapter](ARCHITECTURE.md)
- [Wormhole Technical Brief](WORMHOLE_AEGIS_TECHNICAL_BRIEF.md)

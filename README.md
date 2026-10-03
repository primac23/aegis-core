# AEGIS: Cross-Chain Release Authorization Firewall

**Problem:** Message authentication proves that a source-chain event occurred. It does not prove that the downstream economic release is still valid: a source reorg can orphan the deposit after the message is observed, and reactive `pause()` transactions can lose mempool/MEV races against an in-flight exploit.

**Solution:** A fail-closed authorization layer at the settlement boundary. An asset is released only with a valid M-of-N guardian attestation, on both the standard and emergency paths. No attestation, no release.

## How It Works

1. A deposit on the source chain emits a unique payload: `(recipient, amount, nonce, sourceChainId, sourceContract)`.
2. Guardians wait for source finality (K confirmations) and verify the deposit transaction is still canonical.
3. Guardians sign an EIP-712 attestation over `(messageHash, sourceStateRoot, validAfter, validUntil, sourceBlock, guardianSetId)`.
4. The destination verifies quorum, signer ordering, guardian set, validity window and message binding, marks the message released, then executes.

## Security Properties — 32 Foundry tests, all passing

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
| Wormhole VAA verification | `InvalidVaa`, `UnknownEmitter`, `VaaNotFinalized` | `VaaSignatureInvalid`, `UnknownEmitterChain`, `SpoofedEmitterOnRegisteredChain`, `VaaNotFinalized_Instant`, `VaaNotFinalized_Safe`, `AttestationBoundToRawBytesInsteadOfVaaHash`, `VaaReplayed` |
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

## Guardian Daemon (`engine/`)

A Rust guardian daemon enforces the finality policy in production code:

- Reads `DOMAIN_SEPARATOR` from the destination contract, so its EIP-712 digests match on-chain verification.
- Watches `Deposit` events and classifies each deposit as `Pending`, `Final` (≥ K confirmations and receipt block hash equal to the canonical hash at that height) or `Orphaned`.
- Signs only `Final` deposits. On `Orphaned` it refuses and logs causal-invalidation evidence.
- Uses 60-second aligned validity windows so independent guardians sign identical digests; `engine aggregate` combines ≥ threshold signatures into an on-chain attestation.

`scripts/live_daemon_demo.sh` runs two independent guardian processes against live Anvil chains: a legitimate transfer is released, a source reorg is refused by both guardians (`AttestationMissing`), an identical second transfer is released, and with only one guardian online no quorum forms (fail-closed liveness).

## RPC-Poisoning Resistance (`engine/`)

The April 2026 KelpDAO exploit ($292M) did not require an on-chain bug: compromised RPC nodes fed a forged view of the source chain to a single verifier, which then signed a message for a transfer that never happened. AEGIS guardians defend against this directly: each guardian queries several independent RPC endpoints for the canonical block hash at the deposit's height and signs only when a quorum of them agree. If any endpoint diverges (poisoned or on a different fork), the guardian refuses and logs `RPC-POISON`.

`scripts/live_rpc_poison_demo.sh` demonstrates this with three source RPC nodes, one forced onto a divergent fork: with all three agreeing the guardian signs; with one poisoned, it refuses.

## Scope & Known Limitations (v0.2.0)

- No on-chain light client or state proof; source validity is attested by the guardian quorum.
- `WormholeAegisAdapter` verifies VAAs via `IWormhole.parseAndVerifyVM`, accepts only the registered emitter per source chain, rejects non-finalized consistency levels (200 instant, 201 safe) and binds the AEGIS attestation to the VAA hash. It is tested against a signature-verifying mock and, on an Ethereum mainnet fork, against the deployed Wormhole Core with a real Token Bridge VAA (`AEGIS_FORK_TESTS=true forge test --match-path test/WormholeFork.t.sol`).
- The guardian set is fixed per deployment; rotation requires redeployment.
- The finality policy is implemented in the Rust guardian daemon (`engine/`). Guardian keys are loaded from environment variables; HSM/MPC key custody is a deployment requirement and is not provided.
- No invariant fuzzing or formal verification yet. Verification cost scales with the number of signatures (O(M)).

## Quickstart

Requires [Foundry](https://getfoundry.sh) (`forge`, `anvil`, `cast`).

```bash
cd contracts && forge test -vv          # 32 tests
./scripts/live_reorg_demo.sh            # live dual-chain reorg demo (A–E)
./scripts/live_daemon_demo.sh           # same chains, real Rust guardian daemons (2-of-3)
cd engine && cargo test                 # guardian policy unit tests
```

## Documentation

- [Pilot Specification & Rollout Plan](PILOT_PROPOSAL.md)
- [Threat Model & Security Invariants](THREAT_MODEL.md)
- [Architecture & Integration Adapter](ARCHITECTURE.md)
- [Wormhole Technical Brief](WORMHOLE_AEGIS_TECHNICAL_BRIEF.md)

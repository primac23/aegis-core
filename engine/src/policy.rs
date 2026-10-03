use ethers_core::types::H256;

/// Validity windows are aligned to 60s buckets so independent guardians sign identical digests.
pub const WINDOW_BUCKET_SECS: u64 = 60;
/// Must stay below IFirewallGatedBridge.MAX_ATTESTATION_AGE (120s).
pub const WINDOW_SPAN_SECS: u64 = 119;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceStatus {
    Pending { confirmations: u64 },
    Final,
    Orphaned,
}

/// Finality policy: sign only if the deposit receipt's block is the canonical block at that
/// height AND it has at least `k` confirmations. Anything else is Pending or Orphaned.
pub fn classify(
    receipt_block_hash: Option<H256>,
    canonical_hash_at_height: Option<H256>,
    head: u64,
    block: u64,
    k: u64,
) -> SourceStatus {
    match (receipt_block_hash, canonical_hash_at_height) {
        (Some(r), Some(c)) if r == c => {
            let confirmations = head.saturating_sub(block);
            if confirmations >= k {
                SourceStatus::Final
            } else {
                SourceStatus::Pending { confirmations }
            }
        }
        _ => SourceStatus::Orphaned,
    }
}

pub fn validity_window(now: u64) -> (u64, u64) {
    let after = now - now % WINDOW_BUCKET_SECS;
    (after, after + WINDOW_SPAN_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    const H: H256 = H256::repeat_byte(0x01);
    const OTHER: H256 = H256::repeat_byte(0x02);

    #[test]
    fn final_when_canonical_and_k_confirmations() {
        assert_eq!(classify(Some(H), Some(H), 110, 100, 3), SourceStatus::Final);
    }

    #[test]
    fn final_exactly_at_k() {
        assert_eq!(classify(Some(H), Some(H), 103, 100, 3), SourceStatus::Final);
    }

    #[test]
    fn pending_below_k() {
        assert_eq!(classify(Some(H), Some(H), 102, 100, 3), SourceStatus::Pending { confirmations: 2 });
    }

    #[test]
    fn orphaned_when_receipt_missing() {
        assert_eq!(classify(None, Some(H), 110, 100, 3), SourceStatus::Orphaned);
    }

    #[test]
    fn orphaned_when_block_hash_differs() {
        assert_eq!(classify(Some(H), Some(OTHER), 110, 100, 3), SourceStatus::Orphaned);
    }

    #[test]
    fn window_shared_within_bucket_and_respects_contract_max_age() {
        let base = 1_700_000_000 - 1_700_000_000 % WINDOW_BUCKET_SECS;
        for now in base..base + WINDOW_BUCKET_SECS {
            let (after, until) = validity_window(now);
            assert_eq!((after, until), (base, base + WINDOW_SPAN_SECS));
            assert!(after <= now, "must already be valid");
            assert!(until <= now + 120, "contract rejects validUntil > now + MAX_ATTESTATION_AGE");
            assert!(until >= now + 60, "at least 60s left to submit");
        }
    }
}

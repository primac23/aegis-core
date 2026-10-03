use std::collections::HashMap;
use ethers_core::types::H256;

/// Result of polling several independent RPC endpoints for the canonical block hash
/// at a given height. Agreement is required before a guardian will sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcConsensus {
    /// At least `quorum` endpoints returned the same hash; this is it.
    Agreed(H256),
    /// Endpoints disagree (one or more poisoned, or genuinely on different forks).
    Poisoned { majority: H256, dissenters: usize, total: usize },
    /// Fewer than `quorum` endpoints responded at all.
    Insufficient { responded: usize, quorum: usize },
}

/// Decide consensus from each endpoint's reported hash (None = no response / missing block).
/// `quorum` is the minimum number of endpoints that must agree on one hash.
pub fn consensus(hashes: &[Option<H256>], quorum: usize) -> RpcConsensus {
    let mut tally: HashMap<H256, usize> = HashMap::new();
    let mut responded = 0usize;
    for h in hashes.iter().flatten() {
        *tally.entry(*h).or_insert(0) += 1;
        responded += 1;
    }
    if responded < quorum {
        return RpcConsensus::Insufficient { responded, quorum };
    }
    let (best, agree) = tally.iter().max_by_key(|(_, c)| **c).map(|(h, c)| (*h, *c)).unwrap();
    if agree >= quorum && tally.len() == 1 {
        RpcConsensus::Agreed(best)
    } else {
        RpcConsensus::Poisoned { majority: best, dissenters: responded - agree, total: hashes.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: H256 = H256::repeat_byte(0xAA);
    const B: H256 = H256::repeat_byte(0xBB);

    #[test]
    fn all_agree_is_agreed() {
        assert_eq!(consensus(&[Some(A), Some(A), Some(A)], 3), RpcConsensus::Agreed(A));
    }

    #[test]
    fn one_poisoned_rpc_breaks_consensus() {
        // The Kelp case: two honest endpoints, one feeding a different hash.
        match consensus(&[Some(A), Some(A), Some(B)], 3) {
            RpcConsensus::Poisoned { majority, dissenters, total } => {
                assert_eq!(majority, A);
                assert_eq!(dissenters, 1);
                assert_eq!(total, 3);
            }
            other => panic!("expected Poisoned, got {other:?}"),
        }
    }

    #[test]
    fn too_few_responses_is_insufficient() {
        assert_eq!(
            consensus(&[Some(A), None, None], 3),
            RpcConsensus::Insufficient { responded: 1, quorum: 3 }
        );
    }
}

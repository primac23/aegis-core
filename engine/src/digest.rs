use ethers_core::{
    abi::{encode, Token},
    types::{Address, H256, U256},
    utils::keccak256,
};

/// Must match IFirewallGatedBridge.ATTESTATION_TYPEHASH.
pub const ATTESTATION_TYPEHASH: &str = "FirewallAttestation(bytes32 messageHash,bytes32 sourceStateRoot,uint256 validAfter,uint256 validUntil,uint256 sourceBlock,uint256 guardianSetId)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationFields {
    pub message_hash: H256,
    pub source_state_root: H256,
    pub valid_after: U256,
    pub valid_until: U256,
    pub source_block: U256,
    pub guardian_set_id: U256,
}

#[derive(Clone, Debug)]
pub struct GuardianSig {
    pub signer: Address,
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

/// EIP-712 digest identical to IFirewallGatedBridge.hashTypedAttestation.
pub fn digest(domain_separator: H256, f: &AttestationFields) -> H256 {
    let typehash = keccak256(ATTESTATION_TYPEHASH.as_bytes());
    let struct_hash = keccak256(encode(&[
        Token::FixedBytes(typehash.to_vec()),
        Token::FixedBytes(f.message_hash.as_bytes().to_vec()),
        Token::FixedBytes(f.source_state_root.as_bytes().to_vec()),
        Token::Uint(f.valid_after),
        Token::Uint(f.valid_until),
        Token::Uint(f.source_block),
        Token::Uint(f.guardian_set_id),
    ]));
    let mut packed = Vec::with_capacity(66);
    packed.extend_from_slice(b"\x19\x01");
    packed.extend_from_slice(domain_separator.as_bytes());
    packed.extend_from_slice(&struct_hash);
    H256::from(keccak256(packed))
}

/// abi.encode(MultiAttestation) with signatures sorted strictly ascending by signer.
pub fn encode_attestation(f: &AttestationFields, sigs: &[GuardianSig]) -> Vec<u8> {
    let mut sorted = sigs.to_vec();
    sorted.sort_by_key(|s| s.signer);
    let sig_tokens: Vec<Token> = sorted
        .iter()
        .map(|s| {
            Token::Tuple(vec![
                Token::Uint(U256::from(s.v)),
                Token::FixedBytes(s.r.as_bytes().to_vec()),
                Token::FixedBytes(s.s.as_bytes().to_vec()),
            ])
        })
        .collect();
    encode(&[Token::Tuple(vec![
        Token::FixedBytes(f.message_hash.as_bytes().to_vec()),
        Token::FixedBytes(f.source_state_root.as_bytes().to_vec()),
        Token::Uint(f.valid_after),
        Token::Uint(f.valid_until),
        Token::Uint(f.source_block),
        Token::Uint(f.guardian_set_id),
        Token::Array(sig_tokens),
    ])])
}

pub fn h256_hex(h: H256) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::abi::{decode, ParamType};
    use ethers_signers::{LocalWallet, Signer};

    fn fields() -> AttestationFields {
        AttestationFields {
            message_hash: H256::repeat_byte(0x11),
            source_state_root: H256::repeat_byte(0x22),
            valid_after: U256::from(100u64),
            valid_until: U256::from(219u64),
            source_block: U256::from(7u64),
            guardian_set_id: U256::from(1u64),
        }
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let d = H256::repeat_byte(0xAA);
        let base = digest(d, &fields());
        assert_eq!(base, digest(d, &fields()));
        let mut f = fields();
        f.source_state_root = H256::repeat_byte(0x23);
        assert_ne!(base, digest(d, &f));
        assert_ne!(base, digest(H256::repeat_byte(0xAB), &fields()));
    }

    #[test]
    fn attestation_signatures_sorted_ascending_by_signer() {
        let hi = GuardianSig { signer: Address::repeat_byte(0x02), v: 27, r: H256::repeat_byte(0xB2), s: H256::repeat_byte(0xC2) };
        let lo = GuardianSig { signer: Address::repeat_byte(0x01), v: 28, r: H256::repeat_byte(0xB1), s: H256::repeat_byte(0xC1) };
        let enc = encode_attestation(&fields(), &[hi, lo]);
        let sig_t = ParamType::Tuple(vec![ParamType::Uint(8), ParamType::FixedBytes(32), ParamType::FixedBytes(32)]);
        let att_t = ParamType::Tuple(vec![
            ParamType::FixedBytes(32), ParamType::FixedBytes(32),
            ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(256),
            ParamType::Array(Box::new(sig_t)),
        ]);
        let att = decode(&[att_t], &enc).unwrap()[0].clone().into_tuple().unwrap();
        let sigs = att[6].clone().into_array().unwrap();
        let first = sigs[0].clone().into_tuple().unwrap();
        assert_eq!(first[1].clone().into_fixed_bytes().unwrap(), H256::repeat_byte(0xB1).as_bytes().to_vec());
        assert_eq!(att[0].clone().into_fixed_bytes().unwrap(), H256::repeat_byte(0x11).as_bytes().to_vec());
    }

    #[test]
    fn signature_recovers_to_guardian_address() {
        let w: LocalWallet = "0x0000000000000000000000000000000000000000000000000000000000001111".parse().unwrap();
        let h = digest(H256::repeat_byte(0xAA), &fields());
        let sig = w.sign_hash(h).unwrap();
        assert_eq!(sig.recover(h).unwrap(), w.address());
        assert!(sig.v == 27 || sig.v == 28);
    }
}

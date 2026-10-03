use std::{collections::HashMap, env, fs, path::Path};

use ethers_core::types::U256;

use crate::digest::{encode_attestation, AttestationFields, GuardianSig};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_sig(path: &Path) -> Res<(AttestationFields, GuardianSig)> {
    let text = fs::read_to_string(path)?;
    let kv: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    let get = |k: &str| kv.get(k).copied().ok_or_else(|| format!("{}: missing {k}", path.display()));
    let fields = AttestationFields {
        message_hash: get("message_hash")?.parse()?,
        source_state_root: get("source_state_root")?.parse()?,
        valid_after: U256::from(get("valid_after")?.parse::<u64>()?),
        valid_until: U256::from(get("valid_until")?.parse::<u64>()?),
        source_block: U256::from(get("source_block")?.parse::<u64>()?),
        guardian_set_id: U256::from(get("guardian_set_id")?.parse::<u64>()?),
    };
    let sig = GuardianSig {
        signer: get("signer")?.parse()?,
        v: get("v")?.parse()?,
        r: get("r")?.parse()?,
        s: get("s")?.parse()?,
    };
    Ok((fields, sig))
}

/// Combines >= THRESHOLD guardian signatures over identical fields into an on-chain attestation.
pub fn run() -> Res<()> {
    let dir = env::var("ATTEST_DIR").unwrap_or_else(|_| "./attestations".into());
    let threshold: usize = env::var("THRESHOLD").unwrap_or_else(|_| "2".into()).parse()?;
    let root = Path::new(&dir);
    if !root.exists() {
        println!("[AGGREGATE] nothing to do ({dir} does not exist)");
        return Ok(());
    }
    for msg_entry in fs::read_dir(root)? {
        let msg_dir = msg_entry?.path();
        if !msg_dir.is_dir() {
            continue;
        }
        let name = msg_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
        let mut windows: Vec<u64> = fs::read_dir(&msg_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect();
        windows.sort_unstable_by(|a, b| b.cmp(a));

        let mut ready = false;
        for w in windows {
            let mut sigs: Vec<GuardianSig> = Vec::new();
            let mut reference: Option<AttestationFields> = None;
            for e in fs::read_dir(msg_dir.join(w.to_string()))? {
                let p = e?.path();
                if p.extension().and_then(|x| x.to_str()) != Some("sig") {
                    continue;
                }
                let (f, s) = parse_sig(&p)?;
                if !reference.as_ref().map_or(true, |r| *r == f) {
                    eprintln!("[AGGREGATE] {}: fields differ from quorum, ignored", p.display());
                    continue;
                }
                if reference.is_none() {
                    reference = Some(f);
                }
                sigs.push(s);
            }
            if let (Some(f), true) = (reference, sigs.len() >= threshold) {
                let enc = encode_attestation(&f, &sigs);
                fs::write(msg_dir.join("ready.att"), format!("0x{}\n", hex::encode(enc)))?;
                println!("[READY] msg {name} | window {w} | {} signatures", sigs.len());
                ready = true;
                break;
            }
        }
        if !ready {
            println!("[WAITING] msg {name} | quorum not reached");
        }
    }
    Ok(())
}

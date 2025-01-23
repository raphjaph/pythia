use {
  anyhow::{ensure, Error},
  arguments::Arguments,
  bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{
      rand::{self, prelude::*},
      schnorr::Signature,
      All, Keypair, Message, Secp256k1, XOnlyPublicKey,
    },
  },
  clap::Parser,
  dlc::secp_utils::schnorrsig_sign_with_nonce,
  oracle::Oracle,
  serde::{Deserialize, Serialize},
  std::{env, process},
  subcommand::Subcommand,
};

mod arguments;
mod oracle;
mod subcommand;

type Result<T = (), E = Error> = std::result::Result<T, E>;

const ORACLE_TAG: &str = "DLC/oracle/";
const _ANNOUNCEMENT_TAG: &str = "DLC/oracle/attestation/v0";
const ATTESTATION_TAG: &str = "DLC/oracle/attestation/v0";

// this can be optimized using the midstate pattern (see DLC crate)
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
  let tag_hash = sha256::Hash::hash(tag.as_bytes());
  let mut engine = sha256::HashEngine::default();
  engine.input(tag_hash.as_ref());
  engine.input(tag_hash.as_ref());
  engine.input(message);
  *sha256::Hash::from_engine(engine).as_ref()
}

pub fn main() {
  env_logger::init();

  let args = Arguments::parse();

  match args.run() {
    Err(err) => {
      eprintln!("error: {err}");
      if env::var_os("RUST_BACKTRACE")
        .map(|val| val == "1")
        .unwrap_or_default()
      {
        eprintln!("{}", err.backtrace());
      }

      process::exit(1);
    }

    Ok(_) => {
      process::exit(0);
    }
  }
}

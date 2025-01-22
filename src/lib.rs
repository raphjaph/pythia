use {
  anyhow::{ensure, Error},
  arguments::Arguments,
  bitcoin::hashes::{sha256, Hash},
  clap::Parser,
  oracle::Oracle,
  secp256k1::{
    rand::{self, prelude::*},
    schnorr::Signature,
    All, Keypair, Secp256k1, XOnlyPublicKey,
  },
  serde::{Deserialize, Serialize},
  std::{env, process},
  subcommand::Subcommand,
};

mod arguments;
mod oracle;
mod subcommand;

type Result<T = (), E = Error> = std::result::Result<T, E>;

const ORACLE_TAG: &str = "DLC/oracle/";
const ATTESTATION_TAG: &str = "attestation/v0";

pub fn tagged_message_hash(message: &[u8], tag: &str) -> Vec<u8> {
  let mut tag_hash = sha256::Hash::hash(tag.as_bytes()).to_byte_array().to_vec();
  tag_hash.extend(tag_hash.clone());
  tag_hash.extend(message);

  sha256::Hash::hash(tag_hash.as_slice())
    .to_byte_array()
    .to_vec()
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

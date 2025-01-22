use {
  anyhow::{ensure, Error},
  bitcoin::hashes::{sha256, Hash},
  oracle::Oracle,
  secp256k1::{
    rand::{self, prelude::*},
    schnorr::Signature,
    All, Keypair, Secp256k1, XOnlyPublicKey,
  },
  serde::{Deserialize, Serialize},
  std::{env, process},
};

mod oracle;

type Result<T = (), E = Error> = std::result::Result<T, E>;

const TAG: &str = "DLC/oracle/";

pub fn tagged_message_hash(message: &[u8]) -> Vec<u8> {
  let mut tag_hash = sha256::Hash::hash(TAG.as_bytes()).to_byte_array().to_vec();
  tag_hash.extend(tag_hash.clone());
  tag_hash.extend(message);

  sha256::Hash::hash(tag_hash.as_slice())
    .to_byte_array()
    .to_vec()
}

pub fn run() -> Result {
  let mut oracle = Oracle::new();

  println!("Oracle public key: {}", oracle.keypair.public_key());

  println!("Oracle x only public key: {}", oracle.pub_key());

  println!(
    "Oracle sign message: {}",
    oracle.sign("Hello World".as_bytes())
  );

  let outcome_names = vec!["even".into(), "odd".into()];

  oracle.create_event("even-or-odd".into(), outcome_names)?;

  serde_json::to_writer_pretty(std::io::stdout(), &oracle.events)?;

  Ok(())
}

pub fn main() {
  env_logger::init();

  match run() {
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

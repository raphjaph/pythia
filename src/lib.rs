use {
  anyhow::{ensure, Error},
  bitcoin::hashes::{sha256, Hash},
  secp256k1::{
    rand::{self, prelude::*},
    schnorr::Signature,
    Keypair, Secp256k1, XOnlyPublicKey,
  },
  serde::{Deserialize, Serialize},
  std::{env, process},
};

mod oracle;

use oracle::Oracle;

type Result<T = (), E = Error> = std::result::Result<T, E>;

pub fn run() -> Result {
  let mut oracle = Oracle::new();

  println!("Oracle public key: {}", oracle.keypair.public_key());

  println!("Oracle x only public key: {}", oracle.x_only_pub_key());

  println!(
    "Oracle sign message: {}",
    oracle.sign("Hello World".as_bytes())
  );

  let outcome_names = vec!["even".into(), "odd".into()];

  oracle.create_event("Even or Odd".into(), outcome_names)?;

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

use {
  anyhow::{anyhow, Error},
  bitcoin::hashes::{sha256, Hash},
  secp256k1::{
    rand::{self, prelude::*},
    schnorr::Signature,
    All, Keypair, PublicKey, Secp256k1, XOnlyPublicKey,
  },
  std::{collections::BTreeMap, env, process},
};

mod event;
mod oracle;

use oracle::Oracle;

type Result<T = (), E = Error> = std::result::Result<T, E>;

pub fn run() -> Result {
  let mut oracle = Oracle::new();

  log::info!("Oracle public key: {}", oracle.pub_key());

  log::info!("Oracle x only public key: {}", oracle.x_only_pub_key());

  log::info!(
    "Oracle sign message: {}",
    oracle.sign_message("Hello World".as_bytes())
  );

  let outcomes = vec!["even".into(), "odd".into()];

  oracle.create_event(outcomes)?;

  oracle.print_events();

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

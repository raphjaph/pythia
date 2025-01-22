use {
  anyhow::{ensure, Error},
  arguments::Arguments,
  bitcoin::hashes::{sha256, Hash},
  clap::Parser,
  core::ptr,
  oracle::Oracle,
  secp256k1::{
    rand::{self, prelude::*},
    schnorr::Signature,
    All, Keypair, Message, Secp256k1, Signing, XOnlyPublicKey,
  },
  secp256k1_sys::{
    types::{c_int, c_uchar, c_void, size_t},
    CPtr, SchnorrSigExtraParams,
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
const _ANNOUNCEMENT_TAG: &str = "DLC/oracle/attestation/v0";
const ATTESTATION_TAG: &str = "DLC/oracle/attestation/v0";

pub fn tagged_message_hash(message: &[u8], tag: &str) -> Vec<u8> {
  let mut tag_hash = sha256::Hash::hash(tag.as_bytes()).to_byte_array().to_vec();
  tag_hash.extend(tag_hash.clone());
  tag_hash.extend(message);

  sha256::Hash::hash(tag_hash.as_slice())
    .to_byte_array()
    .to_vec()
}

extern "C" fn constant_nonce_fn(
  nonce32: *mut c_uchar,
  _: *const c_uchar,
  _: size_t,
  _: *const c_uchar,
  _: *const c_uchar,
  _: *const c_uchar,
  _: size_t,
  data: *mut c_void,
) -> c_int {
  unsafe {
    ptr::copy_nonoverlapping(data as *const c_uchar, nonce32, 32);
  }
  1
}

fn sign_schnorr_with_nonce<S: Signing>(
  secp: &Secp256k1<S>,
  msg: &Message,
  keypair: &Keypair,
  nonce: &[u8; 32],
) -> Signature {
  unsafe {
    let mut sig = [0u8; 64];

    let nonce_params =
      SchnorrSigExtraParams::new(Some(constant_nonce_fn), nonce.as_c_ptr() as *const c_void);

    assert_eq!(
      1,
      secp256k1_sys::secp256k1_schnorrsig_sign_custom(
        secp.ctx().as_ptr(),
        sig.as_mut_c_ptr(),
        msg.as_c_ptr(),
        // msg.len(),
        32,
        keypair.as_c_ptr(),
        &nonce_params as *const SchnorrSigExtraParams,
      )
    );

    Signature::from_slice(&sig).unwrap()
  }
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

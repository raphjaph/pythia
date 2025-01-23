use std::str::FromStr;

use super::*;

#[derive(Debug, Parser)]
pub(crate) struct Verify {
  #[arg(long, help = "Oracle public key")]
  public_key: String,
  #[arg(long, help = "Message to verify")]
  message: String,
  #[arg(long, help = "Signature")]
  signature: String,
}

impl Verify {
  pub(crate) fn run(self) -> Result {
    let tagged_hash = tagged_hash(ORACLE_TAG, self.message.as_bytes());
    let message = Message::from_digest(tagged_hash);
    let public_key = XOnlyPublicKey::from_str(&self.public_key)?;
    let signature = Signature::from_str(&self.signature)?;

    Ok(Secp256k1::verification_only().verify_schnorr(&signature, &message, &public_key)?)
  }
}

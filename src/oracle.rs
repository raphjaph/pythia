use super::*;

mod event;
mod outcome;

use event::Event;

const TAG: &str = "DLC/oracle/";

pub fn tagged_message_hash(message: &[u8]) -> Vec<u8> {
  let mut tag_hash = sha256::Hash::hash(TAG.as_bytes()).to_byte_array().to_vec();
  tag_hash.extend(tag_hash.clone());
  tag_hash.extend(message);

  sha256::Hash::hash(tag_hash.as_slice())
    .to_byte_array()
    .to_vec()
}

pub(crate) struct Oracle {
  pub(crate) events: Vec<Event>,
  pub(crate) keypair: Keypair,
}

impl Oracle {
  pub(crate) fn new() -> Self {
    let secp = Secp256k1::new();

    let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());

    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    Self {
      events: Vec::new(),
      keypair,
    }
  }

  pub(crate) fn x_only_pub_key(&self) -> XOnlyPublicKey {
    let (x_only_pub_key, _) = self.keypair.x_only_public_key();

    x_only_pub_key
  }

  pub(crate) fn sign(&self, message: &[u8]) -> Signature {
    let tagged_hash = tagged_message_hash(message);

    Secp256k1::new().sign_schnorr_no_aux_rand(&tagged_hash, &self.keypair)
  }

  pub(crate) fn create_event(&mut self, name: String, outcome_names: Vec<String>) -> Result {
    ensure!(
      !outcome_names.is_empty(),
      "cannot create an event with no outcomes"
    );

    log::info!("Creating event with {} outcomes", outcome_names.len());

    let event = Event::new(name, outcome_names)?;
    self.events.push(event);

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use {super::*, std::assert};

  #[test]
  fn sign_message_with_oracle_pubkey() {
    let oracle = Oracle::new();

    let message = "Hi my name is Pythia";

    let tagged_hash = tagged_message_hash(message.as_bytes());

    let signature = oracle.sign(message.as_bytes());

    assert!(Secp256k1::verification_only()
      .verify_schnorr(&signature, &tagged_hash, &oracle.x_only_pub_key())
      .is_ok());
  }
}

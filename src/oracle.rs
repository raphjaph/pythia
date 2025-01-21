use {super::*, event::Event};

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
  events: Vec<Event>,
  keypair: Keypair,
  secp: Secp256k1<All>,
}

impl Oracle {
  pub(crate) fn new() -> Self {
    let secp = Secp256k1::new();

    let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());

    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    Self {
      events: Vec::new(),
      keypair,
      secp,
    }
  }

  pub(crate) fn pub_key(&self) -> PublicKey {
    self.keypair.public_key()
  }

  pub(crate) fn x_only_pub_key(&self) -> XOnlyPublicKey {
    let (x_only_pub_key, _) = self.keypair.x_only_public_key();

    x_only_pub_key
  }

  pub(crate) fn sign_message(&self, message: &[u8]) -> Signature {
    let tagged_hash = tagged_message_hash(message);

    self
      .secp
      .sign_schnorr_no_aux_rand(&tagged_hash, &self.keypair)
  }

  pub(crate) fn create_event(&mut self, outcomes: Vec<String>) -> Result {
    let event = Event::new(outcomes)?;
    self.events.push(event);

    Ok(())
  }

  pub(crate) fn print_events(&self) {
    for (i, event) in self.events.iter().enumerate() {
      println!("{i}");
      for (outcome, nonce) in event.outcomes.clone() {
        println!("Outcome: {outcome}");
        println!("k: {:?}", nonce);
        println!("R: {}", event.one_time_use_signing_key(&outcome).unwrap());
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use {super::*, std::assert};

  #[test]
  fn sign_message() {
    let oracle = Oracle::new();

    let message = "Hi my name is Pythia";

    let tagged_hash = tagged_message_hash(message.as_bytes());

    let signature = oracle.sign_message(message.as_bytes());

    assert!(Secp256k1::verification_only()
      .verify_schnorr(&signature, &tagged_hash, &oracle.x_only_pub_key())
      .is_ok());
  }
}

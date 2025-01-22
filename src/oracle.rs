use {super::*, event::Event};

mod event;
mod outcome;

pub(crate) struct Oracle {
  pub(crate) events: Vec<Event>,
  pub(crate) keypair: Keypair,
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

  pub(crate) fn pub_key(&self) -> XOnlyPublicKey {
    self.keypair.x_only_public_key().0
  }

  pub(crate) fn sign(&self, message: &[u8]) -> Signature {
    self
      .secp
      .sign_schnorr_no_aux_rand(&tagged_message_hash(message), &self.keypair)
  }

  pub(crate) fn create_event(
    &mut self,
    name: String,
    outcome_labels: Vec<String>,
  ) -> Result<&Event> {
    ensure!(
      !outcome_labels.is_empty(),
      "event must have at least one outcome"
    );

    log::info!(
      "Creating event '{}' with {} outcomes",
      name,
      outcome_labels.len()
    );

    let event = Event::new(name, outcome_labels)?;
    self.events.push(event);

    Ok(
      self
        .events
        .last()
        .expect("should always have at least one event"),
    )
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
      .verify_schnorr(&signature, &tagged_hash, &oracle.pub_key())
      .is_ok());
  }

  #[test]
  fn events() {
    let mut oracle = Oracle::new();

    assert_eq!(oracle.pub_key().serialize().len(), 32);

    let outcome_labels = vec!["even".into(), "odd".into()];

    let event = oracle
      .create_event("even-or-odd".into(), outcome_labels)
      .unwrap()
      .clone();

    assert_eq!(event.outcomes.len(), 2);

    assert_eq!(oracle.events.len(), 1);
  }
}

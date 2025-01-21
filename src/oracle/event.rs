use {super::*, outcome::Outcome};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Event {
  pub(crate) id: String,
  pub(crate) outcomes: Vec<Outcome>,
}

impl Event {
  pub(crate) fn new(id: String, outcome_names: Vec<String>) -> Result<Self> {
    let mut rng = rand::thread_rng();
    let secp = Secp256k1::new();

    let mut outcomes = Vec::new();
    for name in outcome_names {
      let mut nonce = [0u8; 32];
      rng.fill_bytes(&mut nonce);

      let keypair = Keypair::from_seckey_slice(&secp, &nonce)?;

      let (x_only_public_key, _) = keypair.x_only_public_key();

      outcomes.push(Outcome {
        name,
        k: nonce,
        r: x_only_public_key,
      });
    }

    Ok(Self { id, outcomes })
  }
}

use super::*;

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Event {
  pub(crate) outcomes: BTreeMap<String, [u8; 32]>,
}

impl Event {
  pub(crate) fn new(tb_outcomes: Vec<String>) -> Result<Self> {
    let mut rng = rand::thread_rng();

    let mut outcomes = BTreeMap::new();
    for tb_outcome in tb_outcomes {
      let mut nonce = [0u8; 32];
      rng.fill_bytes(&mut nonce);
      outcomes.insert(tb_outcome, nonce);
    }

    Ok(Self { outcomes })
  }

  pub(crate) fn one_time_use_signing_key(&self, outcome: &str) -> Result<XOnlyPublicKey> {
    let Some(nonce) = self.outcomes.get(outcome) else {
      return Err(anyhow!("no outcome found for {outcome}"));
    };

    let secp = Secp256k1::new();

    let keypair = Keypair::from_seckey_slice(&secp, nonce)?;

    let (x_only_public_key, _) = keypair.x_only_public_key();

    Ok(x_only_public_key)
  }
}

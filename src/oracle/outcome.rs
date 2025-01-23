use {super::*, unicode_normalization::UnicodeNormalization};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Outcome {
  pub(crate) label: String,
  pub(crate) secret_nonce: [u8; 32],
  pub(crate) adaptor_point: XOnlyPublicKey,
}

impl Outcome {
  pub(crate) fn new(label: String) -> Result<Self> {
    let mut secret_nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_nonce);

    let keypair = Keypair::from_seckey_slice(&Secp256k1::new(), &secret_nonce)?;

    let (x_only_public_key, _) = keypair.x_only_public_key();

    Ok(Self {
      label,
      secret_nonce,
      adaptor_point: x_only_public_key,
    })
  }

  pub(crate) fn sign(&self, secp: Secp256k1<All>, keypair: Keypair) -> Result<Signature> {
    // https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md#serialization-and-signing-of-outcome-values
    let normalized_label = self.label.nfc().collect::<String>();
    let tagged_hash = tagged_hash(ATTESTATION_TAG, normalized_label.as_bytes());
    let message = Message::from_digest_slice(&tagged_hash)?;

    Ok(schnorrsig_sign_with_nonce(
      &secp,
      &message,
      &keypair,
      &self.secret_nonce,
    ))
  }
}

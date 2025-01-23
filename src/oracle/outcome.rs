use {super::*, unicode_normalization::UnicodeNormalization};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Outcome {
  pub(crate) label: String,
  pub(crate) secret_nonce: [u8; 32],
  pub(crate) adaptor_point: XOnlyPublicKey,
}

impl Outcome {
  pub(crate) fn new(label: String, secp: &Secp256k1<All>) -> Result<Self> {
    let mut secret_nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_nonce);

    let keypair = Keypair::from_seckey_slice(secp, &secret_nonce)?;

    Ok(Self {
      label,
      secret_nonce,
      adaptor_point: keypair.x_only_public_key().0,
    })
  }

  pub(crate) fn sign(&self, keypair: Keypair, secp: Secp256k1<All>) -> Result<Signature> {
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

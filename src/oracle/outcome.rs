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

  pub(crate) fn sign(&self, keypair: &Keypair, secp: &Secp256k1<All>) -> Signature {
    // https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md#serialization-and-signing-of-outcome-values
    let normalized_label = self.label.nfc().collect::<String>();
    let tagged_hash = tagged_hash(ATTESTATION_TAG, normalized_label.as_bytes());

    schnorrsig_sign_with_nonce(
      secp,
      &Message::from_digest(tagged_hash),
      keypair,
      &self.secret_nonce,
    )
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    schnorr_fun::{
      fun::{
        marker::{EvenY, Secret},
        s, Point, Scalar,
      },
      nonce::NoNonces,
      Schnorr,
    },
    serde_json::json,
    sha2::Sha256,
    std::fmt::Write,
  };

  #[test]
  fn signed_outcome_verifies() {
    let secp = Secp256k1::new();
    let oracle = Oracle::new();
    let label: String = "this-is-a-label-for-an-outcome".into();
    let outcome = Outcome::new(label.clone(), &secp).unwrap();
    let signature = outcome.sign(&oracle.keypair, &secp);

    assert!(Secp256k1::verification_only()
      .verify_schnorr(
        &signature,
        &Message::from_digest(tagged_hash(
          ATTESTATION_TAG,
          label.nfc().collect::<String>().as_bytes()
        )),
        &oracle.pub_key()
      )
      .is_ok());
  }

  #[test]
  fn siging_outcome_reveals_secret_nonce() {
    let secp = Secp256k1::new();
    let oracle = Oracle::new();
    let label = "the-sky-falls-on-our-heads".to_string();
    let outcome = Outcome::new(label.clone(), &secp).unwrap();
    let signature = outcome.sign(&oracle.keypair, &secp);

    // extract compressed pub key from xonlypubkey
    // Even y-coordinate according to BIP340
    let adaptor_point =
      Point::<EvenY, Secret, _>::from_xonly_bytes(outcome.adaptor_point.serialize()).unwrap();

    let oracle_pubkey =
      Point::<EvenY, Secret, _>::from_xonly_bytes(oracle.pub_key().serialize()).unwrap();

    let oracle_secret_key: Scalar<Secret> =
      Scalar::from_bytes(*oracle.keypair.secret_key().as_ref())
        .unwrap()
        .non_zero()
        .unwrap();

    let schnorr = Schnorr::<Sha256>::new(NoNonces);

    let challenge: Scalar<Secret> = schnorr
      .challenge(
        &adaptor_point,
        &oracle_pubkey,
        schnorr_fun::Message::raw(&tagged_hash(
          ATTESTATION_TAG,
          label.nfc().collect::<String>().as_bytes(),
        )),
      )
      .non_zero()
      .unwrap();

    let s: Scalar<Secret> = Scalar::from_bytes(signature.as_ref()[32..].try_into().unwrap())
      .unwrap()
      .non_zero()
      .unwrap();

    let rhs = s!(challenge * oracle_secret_key);
    let recovered_nonce = s!(s - rhs);

    assert_eq!(recovered_nonce.to_bytes(), outcome.secret_nonce);
  }

  #[test]
  fn labels_are_normalized_correctly() {
    // From https://github.com/dgarage/NDLC/blob/d816c0c517611b336f09ceaa43d400ecb5ab909b/NDLC.Tests/Data/normalization_tests.json
    let data = json!([
      {
        "Description": "Singleton",
        "Variants": [ "\u{212b}", "\u{0041}\u{030a}", "\u{00c5}" ],
        "Expected": "c385",
        "SHA256": "0a94dc9d420d1142d6b71de60f9bf7e2f345a4d62c9f141b091539769ddf3075"
      },
      {
        "Description": "Canonical Composites",
        "Variants": [ "\u{00f4}", "\u{006f}\u{0302}", "\u{00f4}" ],
        "Expected": "c3b4",
        "SHA256": "cc912dbca598fd80ca7f5d98ece5d846b447f4a9ae3f73c352e2687eb293eef5"
      },
      {
        "Description": "Multiple Combining Marks",
        "Variants": [ "\u{1e69}", "\u{0073}\u{0323}\u{0307}", "\u{1e69}" ],
        "Expected": "e1b9a9",
        "SHA256": "ceca1ea456e95ee498463622915209bb08a018e8ee9741b46b64ef1a08fb56ab"
      },
      {
        "Description": "Compatibility Composites",
        "Variants": [ "\u{fb01}" ],
        "Expected": "efac81",
        "SHA256": "b6554cce8a93f1c8818280e2a768116a79216ad5501a85357d233409db87d340"
      },
      {
        "Description": "Non Composites",
        "Variants": [ "fi" ],
        "Expected": "6669",
        "SHA256": "b4bdc848109722a383d0a972c6eb859f2abd29565b8c4cc7199e7c9eb708f1b7"
      },
      {
        "Description": "Random string",
        "Variants": [ "éléphant" ],
        "Expected": "c3a96cc3a97068616e74",
        "SHA256": "c941ae685f62cbe7bb47d0791af7154788fd9e873e5c57fd2449d1454ed5b16f"
      }
    ]);

    for test in data.as_array().unwrap() {
      for variant in test["Variants"].as_array().unwrap() {
        let normalized = variant.as_str().unwrap().nfc().collect::<String>();

        let hex =
          normalized
            .bytes()
            .fold(String::with_capacity(normalized.len() * 2), |mut acc, b| {
              write!(&mut acc, "{:02x}", b).unwrap();
              acc
            });

        assert_eq!(test["Expected"].as_str().unwrap(), hex);

        let expected_bytes = hex::decode(test["Expected"].as_str().unwrap()).unwrap();

        let sha256_hash = sha256::Hash::hash(&expected_bytes).to_string();

        assert_eq!(test["SHA256"].as_str().unwrap(), sha256_hash);
      }
    }
  }
}

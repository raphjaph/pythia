use {super::*, unicode_normalization::UnicodeNormalization};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Outcome {
  pub(crate) label: String,
  pub(crate) secret_nonce: [u8; 32],
  pub(crate) adaptor_point: XOnlyPublicKey,
}

impl Outcome {
  pub(crate) fn new(label: String, secp: &Secp256k1<All>) -> Result<Self> {
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    let keypair = if public_key.x_only_public_key().1 == Parity::Odd {
      Keypair::from_secret_key(secp, &secret_key.negate())
    } else {
      Keypair::from_secret_key(secp, &secret_key)
    };

    debug_assert_eq!(keypair.x_only_public_key().1, Parity::Even);

    Ok(Self {
      label,
      secret_nonce: secret_key.secret_bytes(),
      adaptor_point: keypair.x_only_public_key().0,
    })
  }

  pub(crate) fn sign(&self, keypair: &Keypair, secp: &Secp256k1<All>) -> Signature {
    let message = self.to_message();
    let sig = schnorrsig_sign_with_nonce(secp, &message, keypair, &self.secret_nonce);

    assert_eq!(sig.serialize()[..32], self.adaptor_point.serialize());

    assert!(secp
      .verify_schnorr(&sig, &message, &keypair.x_only_public_key().0)
      .is_ok());

    sig
  }

  pub(crate) fn to_message(&self) -> Message {
    // https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md#serialization-and-signing-of-outcome-values
    let normalized_label = self.label.nfc().collect::<String>();
    let tagged_hash = tagged_hash(ATTESTATION_TAG, normalized_label.as_bytes());

    Message::from_digest(tagged_hash)
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    bitcoin::{
      hashes::{sha256, Hash},
      secp256k1::SecretKey,
    },
    schnorr_fun::{
      fun::{
        marker::{EvenY, Public, Secret},
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
  fn signing_outcome_reveals_secret_nonce() {
    let secp = Secp256k1::new();
    let oracle = Oracle::new();
    let label = "the-sky-falls-on-our-heads".to_string();
    let outcome = Outcome::new(label.clone(), &secp).unwrap();
    let message = outcome.to_message();
    let signature = outcome.sign(&oracle.keypair, &secp);

    // Verify signature before nonce recovery
    assert!(
      secp
        .verify_schnorr(&signature, &message, &oracle.pub_key())
        .is_ok(),
      "Signature verification failed"
    );

    // Extract R point (first 32 bytes of signature)
    let adaptor_point =
      Point::<EvenY, Public>::from_xonly_bytes(outcome.adaptor_point.serialize()).unwrap();

    // Ensure R point has even Y coordinate per BIP340
    assert_eq!(
      adaptor_point.to_xonly_bytes(),
      signature.as_ref()[..32],
      "R point mismatch"
    );

    let oracle_pubkey =
      Point::<EvenY, Public>::from_xonly_bytes(oracle.pub_key().serialize()).unwrap();

    // Recover nonce
    let s = Scalar::<Secret>::from_bytes(signature.as_ref()[32..].try_into().unwrap()).unwrap();

    let challenge = Schnorr::<Sha256>::new(NoNonces).challenge(
      &adaptor_point,
      &oracle_pubkey,
      schnorr_fun::Message::<Public>::raw(message.as_ref()),
    );

    let oracle_secret_key =
      Scalar::<Secret>::from_bytes(*oracle.keypair.secret_key().as_ref()).unwrap();

    let recovered_nonce = s!(s - challenge * oracle_secret_key);

    // Verify the recovered nonce either matches directly or is the negation
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-generation
    let recovered_bytes = recovered_nonce.to_bytes();
    let original_bytes = outcome.secret_nonce;

    if recovered_bytes != original_bytes {
      let recovered_nonce = SecretKey::from_slice(&recovered_bytes).unwrap();
      let original_nonce = SecretKey::from_slice(&original_bytes).unwrap();

      assert!(
        recovered_nonce.negate() == original_nonce,
        "Recovered nonce neither matches original nor its negation"
      );

      let secp = Secp256k1::new();
      let (ap1, _) = Keypair::from_secret_key(&secp, &recovered_nonce).x_only_public_key();
      let (ap2, _) = Keypair::from_secret_key(&secp, &original_nonce).x_only_public_key();

      assert_eq!(
        ap1, ap2,
        "Adaptor points don't match despite secret key negation"
      );
    } else {
      assert_eq!(recovered_bytes, original_bytes, "Direct key mismatch");
    }

    // Verify that recovered nonce generates correct adaptor point
    let recovered_keypair = Keypair::from_seckey_slice(&secp, &recovered_nonce.to_bytes()).unwrap();

    assert_eq!(
      recovered_keypair.x_only_public_key().0,
      outcome.adaptor_point,
      "Recovered public point mismatch"
    );

    // Verify nonce's public key has even Y coordinate
    assert_eq!(
      recovered_keypair.x_only_public_key().1,
      Parity::Even,
      "Recovered point has odd Y coordinate"
    );
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
              write!(&mut acc, "{b:02x}").unwrap();
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

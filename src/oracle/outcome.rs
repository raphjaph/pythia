use super::*;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Outcome {
  pub(crate) name: String,
  pub(crate) k: [u8; 32],
  pub(crate) r: XOnlyPublicKey,
}

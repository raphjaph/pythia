use {super::*, outcome::Outcome};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct Event {
  pub(crate) id: String,
  pub(crate) outcomes: Vec<Outcome>,
}

impl Event {
  pub(crate) fn new(id: String, outcome_names: Vec<String>) -> Result<Self> {
    let mut outcomes = Vec::new();
    for name in outcome_names {
      outcomes.push(Outcome::new(name)?);
    }

    Ok(Self { id, outcomes })
  }
}

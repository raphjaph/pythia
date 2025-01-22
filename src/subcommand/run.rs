use super::*;

pub fn run() -> Result {
  let mut oracle = Oracle::new();

  println!("Oracle public key: {}", oracle.keypair.public_key());

  println!("Oracle x only public key: {}", oracle.pub_key());

  let outcome_names = vec!["even".into(), "odd".into()];

  let event = oracle
    .create_event("even-or-odd".into(), outcome_names)?
    .clone();

  serde_json::to_writer_pretty(std::io::stdout(), &oracle.events)?;

  let outcome = event.outcomes.first().unwrap();

  println!(
    "\n\nSignature for event {} and outcome {}: {}",
    event.id,
    outcome.label,
    outcome.sign(oracle.secp, oracle.keypair).unwrap()
  );

  Ok(())
}

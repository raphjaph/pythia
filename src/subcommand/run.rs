use super::*;

pub fn run() -> Result {
  let mut oracle = Oracle::new();

  println!("Oracle public key: {}", oracle.keypair.public_key());

  println!("Oracle x only public key: {}", oracle.pub_key());

  let outcome_names = vec!["even".into(), "odd".into()];

  oracle.create_event("even-or-odd".into(), outcome_names)?;

  serde_json::to_writer_pretty(std::io::stdout(), &oracle.events)?;

  Ok(())
}

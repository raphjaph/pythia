use super::*;

mod sign;

#[derive(Debug, Parser)]
pub(crate) enum Subcommand {
  #[command(about = "Run the oracle")]
  Run,
  #[command(about = "Sign a message with the oracle public key")]
  Sign(sign::Sign),
}

impl Subcommand {
  pub(crate) fn run(self) -> Result {
    match self {
      Self::Run => {
        let mut oracle = Oracle::new();

        println!("Oracle public key: {}", oracle.keypair.public_key());

        println!("Oracle x only public key: {}", oracle.pub_key());

        let outcome_names = vec!["even".into(), "odd".into()];

        oracle.create_event("even-or-odd".into(), outcome_names)?;

        serde_json::to_writer_pretty(std::io::stdout(), &oracle.events)?;

        Ok(())
      }
      Self::Sign(sign) => sign.run(),
    }
  }
}

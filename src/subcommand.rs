use super::*;

mod run;
mod sign;
mod verify;

#[derive(Debug, Parser)]
pub(crate) enum Subcommand {
  #[command(about = "Run the oracle")]
  Run,
  #[command(about = "Sign a message with the oracle public key")]
  Sign(sign::Sign),
  #[command(about = "Verify a message from an oracle")]
  Verify(verify::Verify),
}

impl Subcommand {
  pub(crate) fn run(self) -> Result {
    match self {
      Self::Run => run::run(),
      Self::Sign(sign) => sign.run(),
      Self::Verify(verify) => verify.run(),
    }
  }
}

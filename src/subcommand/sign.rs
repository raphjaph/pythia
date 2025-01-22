use super::*;

#[derive(Debug, Parser)]
pub(crate) struct Sign {
  #[arg(long, help = "Message to sign")]
  message: String,
}

impl Sign {
  pub(crate) fn run(self) -> Result {
    let oracle = Oracle::new();
    println!("Message: {}", self.message);

    println!("Public Key: {}", oracle.pub_key());

    println!("Signature: {}", oracle.sign(self.message.as_bytes()));

    Ok(())
  }
}

use {
  anyhow::Error,
  std::{env, process},
};

mod oracle;

type Result<T = (), E = Error> = std::result::Result<T, E>;

pub fn main() {
  env_logger::init();

  match oracle::run() {
    Err(err) => {
      eprintln!("error: {err}");
      if env::var_os("RUST_BACKTRACE")
        .map(|val| val == "1")
        .unwrap_or_default()
      {
        eprintln!("{}", err.backtrace());
      }

      process::exit(1);
    }

    Ok(_) => {
      process::exit(0);
    }
  }
}

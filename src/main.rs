mod cli;
mod utils;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("parameter not setup")]
    ParamNotSetup,
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
}


fn main() -> Result<(), Error> {
    let matches = cli::parse_args();
    let command = cli::get_command(matches);

    match command {
        cli::Command::Read(path) => cli::handle_read(path)?,
        cli::Command::Verify(path) => cli::handle_verify(path)?,
        cli::Command::Aggregate { path, recursive } => cli::handle_aggregate(path, recursive)?,
    }
    Ok(())
}

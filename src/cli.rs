use std::path::Path;
use clap::{App, Arg, SubCommand, ArgMatches};
use bincode::Error;
use snark_verifier_sdk::halo2::read_snark;
use crate::utils::verify;

pub fn parse_args() -> ArgMatches<'static> {
    App::new("Snark Verify CLI")
        .version("1.0")
        .author("snarkify.io")
        .about("Commandline tools for snark proofs aggregation")
        .subcommand(SubCommand::with_name("read")
            .about("Reads data from a specified path")
            .arg(Arg::with_name("path")
                 .help("Path to the data location")
                 .required(true)
                 .index(1)))
        .subcommand(SubCommand::with_name("verify")
            .about("Verifies data at a specified path")
            .arg(Arg::with_name("path")
                 .help("Path to the data location")
                 .required(true)
                 .index(1)))
        .subcommand(SubCommand::with_name("aggregate")
            .about("Aggregates data from a specified path")
            .arg(Arg::with_name("path")
                 .help("Path to the data location")
                 .required(true)
                 .index(1))
            .arg(Arg::with_name("recursive")
                 .help("Aggregate data recursively")
                 .long("recursive")))
        .get_matches()
}

pub enum Command {
    Read(String),
    Verify(String),
    Aggregate { path: String, recursive: bool },
}

pub fn get_command(matches: ArgMatches<'static>) -> Command {
    match matches.subcommand() {
        ("read", Some(sub_m)) => Command::Read(sub_m.value_of("path").unwrap().to_string()),
        ("verify", Some(sub_m)) => Command::Verify(sub_m.value_of("path").unwrap().to_string()),
        ("aggregate", Some(sub_m)) => Command::Aggregate {
            path: sub_m.value_of("path").unwrap().to_string(),
            recursive: sub_m.is_present("recursive"),
        },
        _ => unreachable!(),
    }
}

pub fn handle_read<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    println!("Reading snark from: {:?}", path.as_ref());
    let snark = read_snark(path)?;
    dbg!(snark);
    Ok(())
}

pub fn handle_verify<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    let snark = read_snark(path)?;
    verify(&snark);
    Ok(())
}

pub fn handle_aggregate<P: AsRef<Path>>(path: P, _is_recursive: bool) -> Result<(), Error> {
    println!("Aggregate snarks from: {:?}", path.as_ref());
    // Implement read functionality here
    Ok(())
}

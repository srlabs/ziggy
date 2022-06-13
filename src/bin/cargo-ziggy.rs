use clap::Command;

pub fn cli() -> Command<'static> {
    Command::new("cargo-ziggy").bin_name("cargo").subcommand(
        clap::command!("ziggy")
            .about("A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤")
            .arg_required_else_help(true)
            .subcommand_required(true)
            .allow_external_subcommands(true)
            .allow_invalid_utf8_for_external_subcommands(true)
            .subcommand(
                Command::new("cover")
                    .about("Generate code coverage information using the existing corpus"),
            )
            .subcommand(
                Command::new("fuzz").about("Fuzz targets using different fuzzers in parallel"),
            )
            .subcommand(Command::new("init").about("Create a new fuzzing target"))
            .subcommand(
                Command::new("run")
                    .about("Run a specific input or a directory of inputs to analyze backtrace"),
            ),
    )
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("cover", _)) => {
            todo!();
        }
        Some(("fuzz", _)) => {
            todo!();
        }
        Some(("init", _)) => {
            todo!();
        }
        Some(("run", _)) => {
            todo!();
        }
        _ => unreachable!(),
    }
}

# `ziggy`

`ziggy` is a tool we are building to:
- launch different fuzzers in parallel for all of our fuzzing campaigns, with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

Features will include:

- π€Ή handling of different fuzzing processes in parallel (libfuzzer, honggfuzz, afl++, libafl)
- ποΈ one shared corpus for all fuzzers
- π€ regular corpus minimization
- π insightful monitoring
- π― easy coverage report generation

Features could also include:
- π¨ notification of new crashes via a simple email hook (limited to 1/day to avoid spamming)
- πΆβπ«οΈ Arbitrary trait support ([like here](https://github.com/rust-fuzz/afl.rs/blob/master/examples/arbitrary.rs))
- β¬οΈ Auto-pull of latest target project version

## Usage example

First, you install `ziggy` by running:

```
cargo install ziggy afl honggfuzz
```

Here is the output of the tool's help:

```
$ cargo ziggy
cargo-ziggy 0.1.5
A multi-fuzzer management utility for all of your Rust fuzzing needs π§βπ€

USAGE:
    cargo ziggy <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    build       Build the fuzzer and the runner binaries
    cover       Generate code coverage information using the existing corpus
    fuzz        Fuzz targets using different fuzzers in parallel
    help        Print this message or the help of the given subcommand(s)
    init        Create a new fuzzing target
    minimize    Minimize the input corpus using the given fuzzing target
    run         Run a specific input or a directory of inputs to analyze backtrace
```

For an example fuzz project, see [the url example](./examples/url/).

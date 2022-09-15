# `ziggy`

`ziggy` is a tool we are building to:
- launch different fuzzers in parallel for all of our fuzzing campaigns, with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

Features include:

- 🤹 handling of different fuzzing processes in parallel (LibFuzzer, honggfuzz, AFL++)
- 🗃️ one shared corpus for all fuzzers
- 🤏 regular corpus minimization
- 📊 insightful monitoring
- 🎯 easy coverage report generation
- 😶‍🌫️ Arbitrary trait support

Features will also include:

- 🐇 LibAFL integration
- 📨 notification of new crashes via a simple email hook (limited to 1/day to avoid spamming)
- ⬇️ auto-pull of latest target project version

## Usage example

First, install `ziggy` by running:

```
cargo install ziggy afl honggfuzz grcov
```

Here is the output of the tool's help:

```
$ cargo ziggy
cargo-ziggy 0.2.0
A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤

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

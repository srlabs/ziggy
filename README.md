# `ziggy`

`ziggy` is a fuzzer manager for Rust projects which is built to:

- launch different fuzzers in parallel with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

- 🤹 handling of different fuzzing processes in parallel (honggfuzz, AFL++)
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

First, install `ziggy` and its dependencies by running:

```
cargo install ziggy afl honggfuzz grcov
```

Here is the output of the tool's help:

```
$ cargo ziggy
A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤

Usage: cargo ziggy <COMMAND>

Commands:
  build     Build the fuzzer and the runner binaries
  fuzz      Fuzz targets using different fuzzers in parallel
  run       Run a specific input or a directory of inputs to analyze backtrace
  minimize  Minimize the input corpus using the given fuzzing target
  cover     Generate code coverage information using the existing corpus
  plot      Plot AFL++ data using afl-plot
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

For an example fuzz project, see [the url example](./examples/url/).

## Note about coverage

The `cargo cover` command will not generate coverage for the dependencies of your fuzzed project
by default.

If this is something you would like to change, you can use the following trick:
```
CARGO_HOME=.cargo cargo ziggy cover 
```

This will clone every dependency into a `.cargo` directory and this directory will be included in
the generated coverage.

## `ziggy` logs

If you want to see `ziggy`'s internal logs, you can set `RUST_LOG=INFO`.

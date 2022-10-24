# `ziggy`

`ziggy` is a fuzzer manager for Rust projects which is built to:

- launch different fuzzers in parallel with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

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
  init      Create a new fuzzing target
  build     Build the fuzzer and the runner binaries
  fuzz      Fuzz targets using different fuzzers in parallel
  run       Run a specific input or a directory of inputs to analyze backtrace
  minimize  Minimize the input corpus using the given fuzzing target
  cover     Generate code coverage information using the existing corpus
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

For an example fuzz project, see [the url example](./examples/url/).

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
  init      Create a new fuzzing target
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

The `cargo cover` command will assume two things if you run it without any arguments:
- you are working somewhere within your `$HOME` directory
- your `$CARGO_HOME` is also somewhere within your `$HOME` directory

If one of these assumptions is incorrect, you can use the following workaround:
```
CARGO_HOME=$PROJECT_DIR/.cargo cargo ziggy cover --source $PROJECT_DIR
```

where `$PROJECT_DIR` encapsulates all of the code that you want the fuzzer to cover.
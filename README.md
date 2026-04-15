# `ziggy`

[![Build status](https://github.com/srlabs/ziggy/actions/workflows/ci.yml/badge.svg)](https://github.com/srlabs/ziggy/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/ziggy.svg)](https://crates.io/crates/ziggy)
[![Docs.rs](https://img.shields.io/docsrs/ziggy)](https://docs.rs/ziggy)

`ziggy` is a fuzzer manager for Rust projects which is built to:

- launch different fuzzers in parallel with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

- 🤹 handling of different fuzzing processes in parallel ([honggfuzz](https://github.com/google/honggfuzz), [AFL++](https://github.com/aflplusplus/aflplusplus))
- 🗃️ one shared corpus for all fuzzers
- 🤏 effortless corpus minimization
- 📊 insightful monitoring
- 🎯 easy coverage report generation
- 😶‍🌫️ Arbitrary trait support

Features will also include:

- 🐇 [LibAFL](https://github.com/aflplusplus/libafl) integration
- 📨 notification of new crashes via bash hook

## Usage example

First, install `ziggy` and its dependencies by running:

```bash
cargo install --force ziggy cargo-afl honggfuzz
```

Here is the output of the tool's help:

```text
$ cargo ziggy
A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤

Usage: cargo ziggy <COMMAND>

Commands:
  build      Build the fuzzer and the runner binaries
  fuzz       Fuzz targets using different fuzzers in parallel
  run        Run a specific input or a directory of inputs to analyze backtrace
  minimize   Minimize the input corpus using the given fuzzing target
  cover      Generate code coverage information using the existing corpus
  plot       Plot AFL++ data using afl-plot
  add-seeds  Add seeds to the running AFL++ fuzzers
  triage     Triage crashes found with CASR - currently only works for AFL++
  stability  Analyze harness stability by detecting non-deterministic code paths
  clean      Remove generated artifacts from the target directory
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

To create a fuzzer, simply add `ziggy` as a dependency.

```toml
[dependencies]
ziggy = { version = "1.6.1", default-features = false }
```

Then use the `fuzz!` macro inside your `main` to create a harness.

```rust ignore
fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        println!("{data:?}");
    });
}
```

For a well-documented fuzzer, see [the url example](./examples/url/).

## The `output` directory

After you've launched your fuzzer, you'll find a couple of items in the `output/<target>` directory:

- the `corpus` directory containing the full corpus
- the `crashes` directory containing any crashes detected by the fuzzers
- the `timeouts` directory containing any timeouts/hangs detected by the fuzzers
- the `logs` directory containing fuzzer log files
- the `afl` directory containing AFL++'s output
- the `honggfuzz` directory containing Honggfuzz's output
- the `queue` directory that is used by ziggy to pass items from AFL++ to Honggfuzz

## Coverage

Generate an HTML coverage report from your existing shared corpus:

```bash
cargo ziggy cover
```

The report entry point will be in ziggy's `output` directory at `./<target>/coverage/index.html`.
It can be changed to `<dir>/index.html` using the `-o <dir>` option.

You can select different output formats or specify a custom input corpus:

```bash
cargo ziggy cover \
    -i path/to/corpus \  # custom input corpus directory
    -t html \            # navigable source-level report (default)
    -t text \            # same folder structure as html, but plain-text summaries
    -t json \            # machine-readable per-file data
    -t lcov              # standard tracefile for CI tools like Codecov
```

## Trophy case

[CVE-2026-24116](https://www.cve.org/CVERecord?id=CVE-2026-24116) was found in wasmtime by differential fuzzing with wasmi

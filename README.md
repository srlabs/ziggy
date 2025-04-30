# `ziggy`

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
cargo install --force ziggy cargo-afl honggfuzz grcov
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
  triage     Triage crashes found with casr - currently only works for AFL++
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

To create a fuzzer, simply add `ziggy` as a dependency.

```toml
[dependencies]
ziggy = { version = "1.2", default-features = false }
```

Then use the `fuzz!` macro inside your `main` to create a harness.

```rust
fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        println!("{data:?}");
    });
}
```

For a well-documented fuzzer, see [the url example](./examples/url/).

## The `output` directory

After you've launched your fuzzer, you'll find a couple of items in the `output` directory:

- the `corpus` directory containing the full corpus
- the `crashes` directory containing any crashes detected by the fuzzers
- the `logs` directory containing a fuzzer log files
- the `afl` directory containing AFL++'s output
- the `honggfuzz` directory containing Honggfuzz's output
- the `queue` directory that is used by ziggy to pass items from AFL++ to Honggfuzz

## Note about coverage

The `cargo cover` command will not generate coverage for the dependencies of your fuzzed project
by default.

If this is something you would like to change, you can use the following trick:
```bash
CARGO_HOME=.cargo cargo ziggy cover 
```

This will clone every dependency into a `.cargo` directory and this directory will be included in
the generated coverage.

## Fuzzing C++ codebase: LibFuzzer integration (beta)

Ziggy has the capability to fuzz C++ codebase. You can run the example inside `examples/libfuzzer_c++` for this. In order to do so, you need to have a harness wrapping
`LLVMFuzzerTestOneInput`. As the CMakeLists.txt shows it, you must compile your harness as a library, so Ziggy can use this library and fuzz its main entrypoint.

Ziggy will ensure to compile your target with ASAN, CMPLOG, and generate proper coverage report. 
This is still under construction, so might not work as expected.

## `ziggy` logs

If you want to see `ziggy`'s internal logs, you can set `RUST_LOG=INFO`.

# `ziggy`

`ziggy` is a tool we are building to:
- launch different fuzzers in parallel for all of our fuzzing campaigns, with a shared corpus
- create and monitor continuous fuzzing pipelines

## Feature set

Features will include:

- 🤹 handling of different fuzzing processes in parallel (libfuzzer, honggfuzz, afl++, libafl)
- 🗃️ one shared corpus for all fuzzers
- 🤏 regular corpus minimization
- 📊 insightful monitoring
- 🎯 easy coverage report generation

Features could also include:
- 📨 notification of new crashes via a simple email hook (limited to 1/day to avoid spamming)
- 😶‍🌫️ Arbitrary trait support ([like here](https://github.com/rust-fuzz/afl.rs/blob/master/examples/arbitrary.rs))
- ⬇️ Auto-pull of latest target project version

## Usage example

First, you install `ziggy` by running:
```
cargo install ziggy
```

Here is a potential output of the tool's help:
```
$ cargo ziggy
cargo-ziggy 0.1.0
A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤

USAGE:
    cargo ziggy COMMAND

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

COMMANDS:
    cover   Generate code coverage information using the existing corpus
    fuzz    Fuzz targets using different fuzzers in parallel
    help    Print this message or the help of the given subcommand(s)
    init    Create a new fuzzing target
    run     Run a specific input or a directory of inputs to analyze backtrace
```

Let's say we want to fuzz the `url` crate (which is the example used [here](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)).
First, we clone the `rust-url` repository. Inside of it, we initiate the fuzz project.

```
cargo ziggy init
```

This will create a cargo sub-crate, which can contain a collection of fuzzing targets.

Our harness might look like:

```rust
extern crate url;

// A fuzz target starts with `fuzz_`
pub fn fuzz_url(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = url::Url::parse(&s);
    }
}
```

We can then launch the fuzzers by running:

```
cargo ziggy fuzz
```

This will use sensible defaults (e.g. only use 1/4 of the machine's ressources in total), but some options will be available for `ziggy` and every underlying fuzzer.

For example:
- defining a specific dictionary file
- defining a custom directory for the corpus
- defining the CPUS/threads available

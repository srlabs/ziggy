# Ziggy example - URL

First, install the tooling:

```
cargo install cargo-afl honggfuzz ziggy
```

ASAN mode is only available when using Rust Nightly.

To fuzz, run in this directory:

```
cargo +nightly ziggy fuzz --asan
```

Note: 
The the runner must use ``--asan`` too!
```
cargo +nightly ziggy run --asan
```

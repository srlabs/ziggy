# Ziggy example - URL

First, install the tooling:

```
cargo install cargo-afl honggfuzz ziggy
```

Then, in this directory, run:

```
cargo ziggy fuzz --asan
```

Note: 
The the runner must use ``--asan`` too!
```
cargo ziggy run --asan
```

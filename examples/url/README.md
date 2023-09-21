# Ziggy example - URL

In the root project directory, run:

```
cargo install cargo-afl honggfuzz
cargo install --force --path .
```

Then, in the `examples/url` directory, run:

```
cargo ziggy fuzz
```

# Ziggy example - Arbitrary

In the root project directory, run:

```
cargo install afl honggfuzz
cargo install --force --path .
```

Then, in the `examples/arbitrary` directory, run:

```
cargo ziggy fuzz
```

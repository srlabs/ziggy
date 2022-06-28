# Ziggy example

In the root project directory, run:
```
cargo install afl honggfuzz
cargo install --force --path . --features=cli
```

Then, in the `example` directory, run:
```
cargo ziggy build
cargo ziggy fuzz ziggy-example
```

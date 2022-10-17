# Ziggy example - with lazy_static

In the root project directory, run:

```
cargo install afl honggfuzz
cargo install --force --path .
```

Then, in the `examples/with_lazy_static` directory, run:

```
cargo ziggy fuzz
```

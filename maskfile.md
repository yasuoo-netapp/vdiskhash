# Tasks

Task runner for the `vdiskhash` utility.

## build

Build the project in debug mode.

```bash
cargo build
```

## release

Build the project in release (production) mode.

```bash
cargo build --release
```

## test

Run all unit tests.

```bash
cargo test
```

## clean

Clean all cargo build artifacts and cache.

```bash
cargo clean
```

## benchmark

Run performance benchmarks comparing different parameters.

```bash
bash util/benchmark.sh
```

## integration-test

Run integration tests using qemu-img to verify hash correctness across all formats.

```bash
bash util/integration_test.sh
```

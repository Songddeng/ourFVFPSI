# Equal Fuzzy PSI 
This repository contains the research implementation of fuzzy private set intersection (FPSI) and its prefix-optimized variants.

The main executable is `build/fpsi`. It does not read an external dataset file. Instead, it generates two synthetic sets in memory, injects a controlled overlap, runs the selected FPSI protocol, and prints communication/time statistics.

## Quick Start

Build the project:

```bash
./build.sh
cmake -S . -B build
cmake --build build -j
```

Run one baseline `L_infinity` example:

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -try 1
```

Run one prefix-optimized `L2` example:

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefix -try 1
```

Run the maintained smoke test:

```bash
./build/test_prefilter_filters
```

## What Is In This Repo

- `src/fpsi.cpp`: main non-prefix FPSI implementations.
- `src/fpsi_prefix.cpp`: prefix-optimized FPSI implementations.
- `src/*.cpp`: supporting MPC building blocks such as `SiOPRF`, `SoOPRF`, `SoOPPRF`, `OKVS`, `B2A`, `MUX`, and arithmetic helpers.
- `tests/test_prefilter_bench.cpp`: prefilter benchmark driver.
- `tests/test_prefilter_filters.cpp`: prefilter correctness smoke test.
- `tests/test_id_stats.cpp`: stats helper test.
- `build.sh`: helper script that fetches/builds third-party dependencies.

## Requirements

- Linux on `x86_64` / `AMD64`
- `cmake`
- `g++` with C++20 support
- `make` or Ninja
- Optional: Docker for isolated builds

Packages used by `build.sh`:

```bash
build-essential
cmake
git
libtool
iproute2
python3
sudo
nasm
libssl-dev
libgmp-dev
wget
libfmt-dev
```

## Build

### 1. Fetch dependencies

```bash
./build.sh
```

What `build.sh` currently does:

- builds `secure-join` into `thirdparty/out/install`
- builds `volePSI` into `thirdparty/out/install`
- fetches `FastFilter/xor_singleheader` into `thirdparty/xor_singleheader-master`

### 2. Configure and compile

```bash
cmake -S . -B build
cmake --build build -j
```

The main binary will be:

```bash
./build/fpsi
```

### 3. If your local SecureJoin compatibility stack is in a different path

The current CMake defaults `LEGACY_SECUREJOIN_ROOT` to:

```bash
/home/songdengdeng/Desktop/SecureJoin/secure-join/out/build/linux
```

If your machine uses a different path, configure with:

```bash
cmake -S . -B build -DLEGACY_SECUREJOIN_ROOT=/path/to/secure-join/out/build/linux
```

## Main Program: `build/fpsi`

## What `fpsi` Actually Runs

The executable dispatches by metric `-p` and whether `-prefix` is present:

| Command shape | Internal route | Meaning |
|---|---|---|
| `./build/fpsi ...` or `./build/fpsi -p 0 ...` | `fuzzyPsi()` | baseline `L_infinity` FPSI |
| `./build/fpsi -p 0 -prefix ...` | `fuzzyPsiPrefix()` | prefix-optimized `L_infinity` FPSI |
| `./build/fpsi -p 1 ...` | `fuzzyPsiLp()` | `L1` FPSI |
| `./build/fpsi -p 2 ...` | `fuzzyPsiLp()` | `L2` FPSI |
| `./build/fpsi -p 1 -prefix ...` | `fuzzyPsiLpPrefix()` | prefix-optimized `L1` FPSI |
| `./build/fpsi -p 2 -prefix ...` | `fuzzyPsiLpPrefix()` | prefix-optimized `L2` FPSI |

Important behavior:

- `-p` defaults to `0`, so omitting `-p` runs the `L_infinity` path.
- `-prefix` is a presence flag. Recommended usage is just `-prefix`.
- `-prefilter bfuse` is only implemented in the non-prefix `L1/L2` path (`fuzzyPsiLp`).
- `-reveal_mode` is only meaningful in that same non-prefix `L1/L2` path.
- the main `fpsi` binary does not support `-fpr`; Binary Fuse prefilter configuration is fixed.

## Main Workflow Commands

### 1. Baseline `L_infinity`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -try 1
```

### 2. Prefix-optimized `L_infinity`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -prefix -try 1
```

### 3. Baseline `L1`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 1 -try 1
```

### 4. Baseline `L2`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -try 1
```

### 5. Prefix-optimized `L1`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 1 -prefix -try 1
```

### 6. Prefix-optimized `L2`

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefix -try 1
```

### 7. `L2` with Binary Fuse prefilter, receiver-only reveal

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefilter bfuse -reveal_mode receiver_only -try 1
```

### 8. `L2` with Binary Fuse prefilter, mutual reveal

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefilter bfuse -reveal_mode mutual -try 1
```

### 9. Numeric reveal mode aliases

```bash
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefilter bfuse -reveal_mode 1 -try 1
./build/fpsi -nn 8 -d 8 -delta 16 -p 2 -prefilter bfuse -reveal_mode 0 -try 1
```

## `fpsi` Parameters

| Flag | Scope | Meaning | Default | Notes |
|---|---|---|---|---|
| `-n` | all `fpsi` routes | exact input set size per party | `1 << nn` | if provided, it overrides `-nn` for set size |
| `-nn` | all `fpsi` routes | log2 set size helper | `10` | if `-n` is omitted, size becomes `2^nn` |
| `-d` | all `fpsi` routes | vector dimension | `2` | each record is a `d`-dimensional integer vector |
| `-delta` | all `fpsi` routes | fuzzy distance threshold | `2` | use powers of two where possible; prefix code assumes supported table entries |
| `-p` | all `fpsi` routes | metric selector | `0` | `0 = L_infinity`, `1 = L1`, `2 = L2` |
| `-try` | all `fpsi` routes | number of repeated runs for averaging | `1` | summary output is averaged over runs |
| `-v` | all `fpsi` routes | verbose mode | `0` | `1` prints stage timing tables, `2` also prints per-item intersection details |
| `-prefix` | prefix routes only | enable prefix-optimized protocol path | off | presence flag; recommended form is just `-prefix` |
| `-prefilter` | non-prefix `L1/L2` only | enable prefilter before the main `L1/L2` protocol | off | only `bfuse` is supported in the main path |
| `-reveal_mode` | non-prefix `L1/L2` only | choose who learns the intersection | `receiver_only` | accepts `mutual`, `receiver_only`, `0`, `1`, plus compatibility synonyms |
| `-sf` / `-safe_filter` | non-prefix `L1/L2` only | legacy alias of `-reveal_mode` | unset | `0 -> mutual`, `1 -> receiver_only` |
| `-s` | prefix `L1/L2` route | prefix shift parameter | `0` | consumed by `fuzzyPsiLpPrefix()` only |

### Real notes about `-nn`

The current synthetic driver also uses `nn` as the default overlap count:

- when you run `-nn 8`, the generated true intersection size is `8`
- if you specify `-n` but omit `-nn`, the code falls back to a small fixed overlap default from the implementation

So in this repo, `-nn` is not only a size helper for `n`; it also affects the synthetic workload shape.

### Real notes about prefiltering

- main-path prefilter support exists only in `fuzzyPsiLp()` (`-p 1` or `-p 2`, without `-prefix`)
- supported value is `-prefilter bfuse`
- `-reveal_mode mutual` requires `-prefilter bfuse`
- `-fpr` is intentionally rejected by `build/fpsi`

## Typical Output

For a successful run, `fpsi` prints one summary line plus a stats block. Example:

```text
[ours]       L2       8    16    256    7.435      0.570      4.670      2.687      0.077
[id-stats] fpsiFilterLp
  Intersection_Context: True_Intersection_Estimate = 8
  Filter_Execution_Result: R_Total_Hits = 8 | R_Blocked_Useless = 248
```

The summary columns are:

```text
[Protocol] [Metric] [Dim] [Delta] [SetSize] [Comm(MB)] [Time(s)] [FMapComm(MB)] [FilterComm(MB)] [OTComm(MB)]
```

## Tests and Benchmarks

### Build all maintained test targets

```bash
cmake --build build -j --target test_prefilter_filters test_prefilter_bench test_id_stats
```

### 1. Prefilter correctness smoke test

```bash
./build/test_prefilter_filters
```

What it checks:

- filter name parsing
- serialization/deserialization
- no false negatives on a synthetic dataset
- currently covers Bloom, Virtual Bloom, Cuckoo, XOR, and Binary Fuse in the benchmark/helper layer

### 2. Prefilter benchmark

Run all benchmarked filters:

```bash
./build/test_prefilter_bench -filter all -n 32768 -truth 28 -fpr 1e-3 -try 1
```

Run Binary Fuse only:

```bash
./build/test_prefilter_bench -filter bfuse -n 4096 -truth 128 -try 1
```

Prefilter benchmark parameters:

| Flag | Meaning | Default | Notes |
|---|---|---|---|
| `-filter` | which benchmark filter(s) to run | `all` | accepts `all`, `bloom`, `vbf`, `cuckoo`, `xor`, `bfuse` |
| `-n` | receiver candidate count | `32768` | this is benchmark dataset size, not the main `fpsi` set size flag meaning |
| `-truth` | true intersection count | `28` | number of real hits injected into the benchmark dataset |
| `-seed` | dataset RNG seed | `0` | useful for reproducibility |
| `-fpr` | target false positive rate | `1e-3` | valid for the benchmark tool; not accepted by main `fpsi` |
| `-try` | repeated runs for averaging | `1` | averages the printed metrics |

### 3. Stats helper test

```bash
./build/test_id_stats
```

This validates helper formulas such as invalidation rate and redundancy calculations.

## Convenience Scripts

### Non-prefix benchmark sweep

```bash
./bench1.sh
```

This runs several `fpsi` combinations over:

- `nn = 8, 12, 16`
- `d = 4, 8, 16`
- `delta = 16, 32`
- `p = 0, 1, 2`

### Prefix benchmark sweep

```bash
./bench2.sh
```

This runs prefix-enabled `fpsi` combinations over:

- `nn = 12`
- `d = 8`
- `delta = 16, 64, 256, 1024`
- `p = 0, 1, 2`

### Optional loopback network throttling

```bash
./throttle.sh lan
./throttle.sh wan
./throttle.sh del
```

`throttle.sh` uses Linux `tc` on the loopback device `lo` to emulate LAN/WAN conditions.

## Baseline References

### Gao et al.

[Code](https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping)  
[Paper](https://eprint.iacr.org/2024/1462)

Recommended Docker image:

```text
blueobsidian/gao_artifact:latest
```

### Dang et al.

[Code](https://github.com/zhouxv/ourFuzzyPSI-C)  
[Paper](https://eprint.iacr.org/2025/1796)

Recommended Docker image:

```text
blueobsidian/fpsi_artifact:latest
```

## Acknowledgements

Parts of this codebase, especially the prefix-optimization branch, are adapted from:

- [zhouxv/ourFuzzyPSI-C](https://github.com/zhouxv/ourFuzzyPSI-C)

## Citation

```bibtex
@INPROCEEDINGS{
    author = { Yang, Xinpeng and Hao, Meng and Weng, Chenkai and Deng, Robert H. and Wen, Yonggang and Zhang, Tianwei },
    booktitle = { 2026 IEEE Symposium on Security and Privacy (SP) },
    title = {{ Efficient Fuzzy Private Set Intersection from Secret-shared OPRF }},
    year = {2026},
}
```

# Efficient Fuzzy Private Set Intersection from Secret-shared OPRF

This repository provides the implementation and build scripts for fuzzy private set intersection.

> Note: This project is experimental and primarily intended for research use. Adjust parameters according to your hardware and dataset sizes.


## Location of Main Functionality
- `src/*.cpp` contains the implementations of our building blocks such as `si-OPRF`, `so-OPRF`, `so-OPPRF` and other MPC components
- `src/fpsi.cpp` contains the implementations of basic `fuzzy mapping`, `fuzzy PSI` protocol
- `src/fpsi_prefix.cpp` contains the implementations of **prefix-optimized** `fuzzy mapping`, `fuzzy PSI` protocol

## Requirements

- Linux on **AMD64** Only
- `cmake`, `make`, `g++ 13`
- Docker (optional, for isolated builds)
- Additional third-party libraries [secure-join](https://github.com/Visa-Research/secure-join.git) and [volePSI](https://github.com/ladnir/volepsi.git) (can be installed by the script [build.sh](./build.sh))


- **Dependencies :**

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

## Local build

From the project root directory:

```bash
./build.sh    # installs third-party dependencies if needed (about 10-15 mins)
mkdir -p build && cd build
cmake ..
make -j

# The executable will be located at ./build/fpsi
```

## Docker (optional)

Use Docker for an isolated or reproducible build environment:

```bash
docker build -t <your-image-name> .
docker run -it --name <your-container-name> --cap-add=NET_ADMIN --memory=512g <your-image-name>
docker exec -it <your-container-name> bash
```

## Command-line Options

Below are the commonly used command-line flags. Flags use a leading dash (for example `-nn`, `-d`).

| Flag | Meaning | Values / Notes |
|---|---|---|
| `-d` | Dimension | integer |
| `-m` | Metric | `0`: $L_\infty$, `1`: $L_1$, `2`: $L_2$ |
| `-delta` | Distance threshold (δ) | recommended to be a power of 2 |
| `-nn` | log2 of input set size (n) | tested values: `8`~`16` |
| `-v` | Verbosity | `0`: off (default), `1`: info |
| `-try` | Number of runs | integer, default `1` |
| `-prefix` | Prefix optimization flag | `0`: off (default), `1`: on |

## Usage Examples

Run a basic fuzzy PSI experiment:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1
```

Enable prefix optimization:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -prefix 1
```

------------------------------------------------------------------------

## Baseline Implementations

The following baseline implementations are used for comparison.

### Gao et al. 
[Code](https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping) |   [Paper](https://eprint.iacr.org/2024/1462)

Recommended Docker image:

    blueobsidian/gao_artifact:latest

------------------------------------------------------------------------

### Dang et al.

[Code](https://github.com/zhouxv/ourFuzzyPSI-C) | [Paper](https://eprint.iacr.org/2025/1796)

Recommended Docker image:

    blueobsidian/fpsi_artifact:latest

------------------------------------------------------------------------

## Acknowledgements
Parts of this codebase (for prefix optimization) are adapted from [zhouxv/ourFuzzyPSI-C](https://github.com/zhouxv/ourFuzzyPSI-C)


## Citation

If you make use of our work, please consider citing us:

```bibtex
@INPROCEEDINGS{
    author = { Yang, Xinpeng and Hao, Meng and Weng, Chenkai and Deng, Robert H. and Wen, Yonggang and Zhang, Tianwei },
    booktitle = { 2026 IEEE Symposium on Security and Privacy (SP) },
    title = {{ Efficient Fuzzy Private Set Intersection from Secret-shared OPRF }},
    year = {2026},
}
```

## ton-address-miner

CUDA-based multisig address miner for TON

### Requirements

- CMake 3.17+
- CUDA 11.2+
- CUDA compatible GPU

### How to build

```
git clone https://github.com/Rexagon/ton-address-miner.git
mkdir -p ton-address-miner/build && cd ton-address-miner/build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target ton_address_miner -- -j
```

## ton-address-miner

Simple and fast multisig address miner for TON

### How to build

```
git clone https://github.com/Rexagon/ton-address-miner.git
mkdir -p ton-address-miner/build && cd ton-address-miner/build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target mineaddr -- -j
```

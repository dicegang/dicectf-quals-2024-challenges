#!/bin/sh
cd "$(dirname $0)"
sudo docker run -v $(pwd):/sources ethereum/solc:0.8.22 --abi --bin --overwrite -o /sources/build \
    /sources/pow.sol \
    /sources/Distributor.sol \
    /sources/solution.sol

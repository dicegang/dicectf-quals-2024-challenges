#!/bin/sh

cd $(dirname $0)
rm -rf ./floordrop
mkdir floordrop
cp solve.py floordrop
cp ../contracts/pow.sol floordrop
cp genesis.json floordrop
zip -r floordrop.zip floordrop
rm -r ./floordrop
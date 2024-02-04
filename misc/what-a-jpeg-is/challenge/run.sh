#!/bin/sh
cp -r cache /tmp/cache
cp challenge.py flag.txt /tmp/
cd /tmp/
python3 challenge.py
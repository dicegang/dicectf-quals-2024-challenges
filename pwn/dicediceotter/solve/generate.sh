#!/bin/bash

set -eux

GADGETS=$1

rg ": pop rdi; ret;$" $GADGETS | head -n 1
rg ": pop rsi; ret;$" $GADGETS | head -n 1
rg ": pop rdx; ret;$" $GADGETS | head -n 1
rg ": pop rax; ret;$" $GADGETS | head -n 1
rg ": syscall; ret;$" $GADGETS | head -n 1

#!/bin/sh
# not part of the challenge, just disables full buffering

exec script -E never -q -c "./boogie-woogie" /dev/null

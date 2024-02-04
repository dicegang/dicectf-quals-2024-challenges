#!/bin/sh
set -e
set -x
echo 'clone_newnet: false' >> /tmp/nsjail.cfg
cp /etc/resolv.conf /srv/etc/resolv.conf

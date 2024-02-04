cp -r challenge another-csp
tar --owner="root" --group="root" -H v7 --no-xattr --mtime=1970-01-01T00:00Z -czvf another-csp.tar.gz another-csp
rm -rf another-csp
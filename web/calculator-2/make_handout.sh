cp -r challenge calculator
tar --owner="root" --group="root" -H v7 --no-xattr --mtime=1970-01-01T00:00Z -czvf calculator.tar.gz calculator
rm -rf calculator
cp -r handout gpwaf
tar --owner="root" --group="root" -H v7 --no-xattr --mtime=1970-01-01T00:00Z -czvf gpwaf.tar.gz gpwaf
rm -rf gpwaf
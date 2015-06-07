cd ../posts
for file in *.md; do
    if [ ! -e $file.sig ]; then
        gpg --armor --output $file.sig --detach-sig $file
    fi
done

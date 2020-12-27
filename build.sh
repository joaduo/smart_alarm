#!/bin/bash
if ! pandoc --from=markdown --to=rst --output=README README.md ; then
    echo "pandoc command failed. Copying file without RST conversion"
    cp README.md README
fi

app="smart_alarm"

rm dist/$app\-*.tar.gz

pip3 install twine

python3 setup.py sdist && twine check dist/$app\-*.tar.gz

exit $?

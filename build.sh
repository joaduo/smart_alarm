#!/bin/bash
if ! pandoc --from=markdown --to=rst --output=README README.md ; then
    echo "pandoc command failed. Copying file without RST conversion"
    cp README.md README
fi

app="smart_alarm"

if ls dist/$app\-*.tar.gz > /dev/null ; then
    rm dist/$app\-*.tar.gz
fi

if ! type twine > /dev/null ; then
    pip3 install twine
fi

python3 setup.py sdist && twine check dist/$app\-*.tar.gz
exit $?

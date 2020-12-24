#!/bin/bash
if ! pandoc --from=markdown --to=rst --output=README README.md ; then
    echo "pandoc command failed. Probably it's missing. Aborting."
    exit 1
fi

app="smart_alarm"

rm dist/$app\-*.tar.gz

pip install twine

python3 setup.py sdist && twine check dist/$app\-*.tar.gz

exit $?

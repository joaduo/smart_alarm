#!/bin/bash

cd "$(dirname "$0")"
if ! ./build.sh ; then
    echo "Could not build package."
    exit 1
fi

app="smart_alarm"

pip3 uninstall smart_alarm

pip3 install dist/$app\-*.tar.gz

exit $?

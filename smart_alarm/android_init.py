#!/usr/bin/env python
"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.

(Works on Python 2.7 too, for old Android devices)
"""
import androidhelper
import logging

try:
    droid = androidhelper.Android()
    print('SL4A: Connection OK')
except Exception as e:
    if str(e) == '[Errno 111] Connection refused':
        # socket.error
        print('SL4A: Connection refused')
    else:
        logging.basicConfig()
        logging.exception('While testing SL4A')
        print('SL4A: Other error %r %s %s' % (e,e,type(e)))


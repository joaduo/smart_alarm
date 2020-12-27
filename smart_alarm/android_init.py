import androidhelper
import logging
import socket

try:
    droid = androidhelper.Android()
    print(droid)
    print('SL4A: Connection OK')
except socket.error as e:
    logging.basicConfig()
    logging.exception('While testing SL4A')
    if str(e) == '[Errno 111] Connection refused':
        print('SL4A: Connection refused')

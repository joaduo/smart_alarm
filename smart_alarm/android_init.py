import androidhelper
import logging

try:
    droid = androidhelper.Android()
    print(droid)
except:
    logging.basicConfig()
    logging.exception('While testing SL4A')

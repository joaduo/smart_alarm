"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
from setuptools import setup, find_packages
import six
import os


name = 'smart_alarm'

reqs = ''''''.splitlines()


def long_description():
    with open('README', 'r') as f:
        if six.PY3:
            return f.read()
        else:
            return unicode(f.read())


setup(
  name = name,
  packages = find_packages(),
  version = '1.0',
  description = 'Smarter DVR/NVR alarms',
  long_description=long_description(),
  long_description_content_type='text/x-rst',
  author = 'Joaquin Duo',
  author_email = 'joaduo@gmail.com',
  license='LGPL',
  url = 'https://github.com/joaduo/'+name,
  keywords = ['alarm', 'nvr', 'android', 'smtp', 'sms'],
  install_requires=reqs,
  scripts=[os.path.join(name, 'commands', p)
        for p in os.listdir(os.path.join(os.path.dirname(__file__), name, 'commands'))
  ],
)

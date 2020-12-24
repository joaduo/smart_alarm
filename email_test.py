"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""

import smtplib


server = smtplib.SMTP('127.0.0.1', 1025)
server.set_debuglevel(True)  # show communication with the server
try:
    with open('email.example.txt') as fp:
        server.sendmail('example@mail.com',
                    ['recipient@mail.com'],
                    fp.read())
finally:
    server.quit()

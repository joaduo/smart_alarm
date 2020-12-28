"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import smtplib
from email.message import EmailMessage


def complex_email():
    server = smtplib.SMTP('127.0.0.1', 1025)
    server.set_debuglevel(True)  # show communication with the server
    try:
        with open('email.example.txt') as fp:
            server.sendmail('example@mail.com',
                        ['recipient@mail.com'],
                        fp.read())
    finally:
        server.quit()

def simple():
    msg = EmailMessage()
    msg['Subject'] = 'Subject'
    msg['From'] = 'me'
    msg['To'] = 'you'
    s = smtplib.SMTP('127.0.0.1', 1025)
    s.set_debuglevel(True)
    try:
        s.send_message(msg)
    finally:
        s.quit()


if __name__ == '__main__':
    simple()
    complex_email()

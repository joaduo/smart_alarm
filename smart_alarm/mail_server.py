"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import smtpd
import asyncore
import requests
import argparse
import email
import logging
import re
import os


logger = logging.getLogger('mail_server')


CMDS_SERVER = os.environ.get('CMDS_SERVER', '127.0.0.1')
CMDS_SERVER_PORT = int(os.environ.get('CMDS_SERVER_PORT', '8000'))
CMDS_AUTH_TOKEN= os.environ.get('CMDS_AUTH_TOKEN')

MAIL_LISTEN_ADDRESS = os.environ.get('MAIL_LISTEN_ADDRESS', '127.0.0.1')
MAIL_LISTEN_PORT = int(os.environ.get('MAIL_LISTEN_PORT', '1025'))

NOTIFICATION_TEMPLATE = os.environ.get('NOTIFICATION_TEMPLATE', 'Alarm in {title} {timestamp}.')

MAIL_NVR_CHANNELS=eval(os.environ.get('MAIL_NVR_CHANNELS', '""')) or dict(Garage=2, Garden=1)


class CustomSMTPServer(smtpd.SMTPServer):
    def send_notification(self, msg):
        url = f'http://{CMDS_SERVER}:{CMDS_SERVER_PORT}/alarm/notification/' 
        json = {'msg_from':'smart_alarm.mail_server',
                'msg_type':'SMS',
                'msg':msg,
                'auth_token': CMDS_AUTH_TOKEN}
        try:
            r = requests.post(url, json=json)
            logger.info(f'Got {r} for {msg!r}')
            return r.json()
        except Exception:
            logging.exception(f'While sending {msg!r}')

    def extract_msg(self, data):
        if isinstance(data, str):
            em = email.message_from_string(data)
        else:
            em = email.message_from_bytes(data)
        if em.is_multipart():
            # No test email are multipart (they have attachment)
            em = em.get_payload()[0]
        return em.get_payload()

    def process_msg(self, msg):
        channel_name = {v:k for k,v in MAIL_NVR_CHANNELS.items()}
        if 'detected motion alarm' in msg:
            # 'This is a NVR alarm mail:FN3108XE channel:2 detected motion alarm at 2020-12-21 02:01:38 \n'
            m = re.search('channel:([0-9]+\s).*\s([0-9\-]+\s[0-9:]+)\s', msg)
            channel, timestamp = m.groups()
            channel = int(channel)
            title = channel_name.get(channel, 'channel:%s' % channel).replace('_', ' ')
            msg = NOTIFICATION_TEMPLATE.format(title=title, timestamp=timestamp)
        return msg

    count = 0
    def dump_email(self, data):
        self.count += 1
        fname = f'/tmp/smart_alarm_email.{self.count}.txt'
        with open(fname, 'wb') as fp:
            logger.info(f'Saving {fname}...')
            fp.write(data)

    def process_message(self, peer, mailfrom, rcpttos, data, **options):
        logger.info('Receiving message from: %s', peer)
        logger.info('Message addressed from: %s', mailfrom)
        msg = self.extract_msg(data)
        msg = self.process_msg(msg)
        logger.info('Message msg: %s', msg)    
        self.send_notification(msg)


def main():
    global MAIL_LISTEN_ADDRESS, MAIL_LISTEN_PORT, CMDS_AUTH_TOKEN
    logging.basicConfig()
    logger.setLevel(logging.INFO)
    parser = argparse.ArgumentParser(description='Custom SMTP server')
    parser.add_argument(
        '-l',
        '--listen',
        default=MAIL_LISTEN_ADDRESS,
        help='IP listening address. default=%s' % MAIL_LISTEN_ADDRESS,
    )
    parser.add_argument(
        '-p',
        '--port',
        type=int,
        default=MAIL_LISTEN_PORT,
        help='Listening port. default=%s' % MAIL_LISTEN_PORT,
    )
    parser.add_argument(
        '-t',
        '--token',
        default=CMDS_AUTH_TOKEN,
        help='Authentication secret token',
    )
    args = parser.parse_args()
    MAIL_LISTEN_ADDRESS = args.listen
    MAIL_LISTEN_PORT = args.port
    CMDS_AUTH_TOKEN = args.token
    _ = CustomSMTPServer((MAIL_LISTEN_ADDRESS, MAIL_LISTEN_PORT), None)
    logger.info(f'Starting Mail server at smtp://{MAIL_LISTEN_ADDRESS}:{MAIL_LISTEN_PORT}')
    asyncore.loop()


if __name__ == "__main__":
    main()

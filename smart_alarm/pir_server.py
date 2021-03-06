"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import threading
import os
import requests
import logging
from signal import pause

from gpiozero import MotionSensor
from smart_alarm.solve_settings import solve_settings

logger = logging.getLogger('pir_server')


CMDS_SERVER = os.environ.get('CMDS_SERVER', '127.0.0.1')
CMDS_SERVER_PORT = int(os.environ.get('CMDS_SERVER_PORT', '8000'))
CMDS_AUTH_TOKEN= os.environ.get('CMDS_AUTH_TOKEN')


def setup_and_run():
    # Raspberry Pi GPIO pin config
    sensor = MotionSensor(solve_settings().pir_pin_number)
    def send_notification():
        url = f'http://{CMDS_SERVER}:{CMDS_SERVER_PORT}/alarm/notification/' 
        json = {'msg_from':'smart_alarm.pir_server',
                'msg_type':'PIR',
                'msg':'Motion Detected',
                'auth_token': CMDS_AUTH_TOKEN}
        try:
            r = requests.post(url, json=json)
            logger.info(f'Got {r}')
            return r.json()
        except Exception:
            logging.exception('While sending')
    def on_motion():
        logger.info('Motion detected!')
        threading.Thread(target=send_notification).start()
    def no_motion():
        logger.info('No motion.')    
    logger.info('Setting up the PIR sensor...')
    sensor.wait_for_no_motion()
    logger.info('Waiting for events!')
    sensor.when_motion = on_motion
    sensor.when_no_motion = no_motion
    # Apparently we only need to pause the program while
    # a thread in the back takes care of dispatching events
    pause()


def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    setup_and_run()


if __name__ == '__main__':
    main()

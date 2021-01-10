"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel
import os
import logging
from smart_alarm.cmds_server_helper import User, get_current_active_user, app,\
    AndroidRPC
from fastapi_utils.tasks import repeat_every
import json
import uvicorn

logger = logging.getLogger('cmds_server')
logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)


def split_phones(phones_str):
    return [p.strip() for p in phones_str.split(',') if p.strip()]

SMS_CHECK_SECONDS=int(os.environ.get('SMS_CHECK_SECONDS', '5'))
CMDS_SERVER = os.environ.get('CMDS_SERVER', '127.0.0.1')
CMDS_SERVER_PORT = int(os.environ.get('CMDS_SERVER_PORT', '8000'))
CMDS_AUTH_TOKEN= os.environ.get('CMDS_AUTH_TOKEN')
LOCAL_PHONES_PREFIX = os.environ.get('LOCAL_PHONES_PREFIX','')
ALARM_NOTIFIED_PHONES = split_phones(os.environ.get('ALARM_NOTIFIED_PHONES', ''))
ALARM_ADMIN_PHONES = split_phones(os.environ.get('ALARM_ADMIN_PHONES', ''))

assert CMDS_AUTH_TOKEN

class AlarmCfg:
    notified_phones = ALARM_NOTIFIED_PHONES
    admin_phones = ALARM_ADMIN_PHONES
    enabled = False
    sms_check_seconds = SMS_CHECK_SECONDS
    reply_msgs = True


counter = 0
sms_rcv = dict(msgs=[], ids=set())
@app.on_event("startup")
@repeat_every(seconds=SMS_CHECK_SECONDS, logger=logger, wait_first=True)
def periodic():
    msgs = AndroidRPC().sms_get_messages(unread=True)
    if msgs.get('error'):
        logger.error(f'While checking incoming SMS: {msgs}')
        return
    new_messages = set()
    for m in msgs['result']['rpc_result']['result']:
        if m['_id'] not in sms_rcv['ids']:
            new_messages.add(m['_id'])
            sms_rcv['ids'].add(m['_id'])
            sms_rcv['msgs'].append(m)
            process_cmd(m)
    if new_messages:
        AndroidRPC().smsMarkMessageRead(list(new_messages),True)
        with open('msgs.json', 'w') as fp:
            json.dump(sms_rcv['msgs'], fp, indent=1)


def process_cmd(msg):
    # msg = {'read': '0', 'body': 'Tes',     '_id': '4', 'date': '1610213710004', 'address': '+1...'}
    cmd = msg.get('body')
    cmd = cmd.upper()
    if msg.get('address') in AlarmCfg.admin_phones:
        if cmd.startswith('ON'):
            AlarmCfg.enabled = True
            logger.info('Enabling alarm')
            reply_msg(msg, 'Alarm Enabled')
        elif cmd.startswith('OFF'):
            AlarmCfg.enabled = False
            logger.info('Disabling alarm')
            reply_msg(msg, 'Alarm Disabled')
        elif cmd.startswith('STATUS'):
            # TODO: check if NVR + cameras are online + etc
            logger.info('Sending status')
            reply_msg(msg, build_status())
    else:
        logger.info(f'Unknown command {msg}')


def build_status():
    def removeprefix(s, pref):
        if s.startswith(pref):
            return s[len(pref):]
        return s
    admin = ','.join(removeprefix(p, LOCAL_PHONES_PREFIX) for p in AlarmCfg.admin_phones)
    notify = ','.join(removeprefix(p, LOCAL_PHONES_PREFIX) for p in AlarmCfg.notified_phones)
    return f'Enabled:{AlarmCfg.enabled} Admins:{admin} Notify:{notify}'


def reply_msg(msg, reply_body):
    if AlarmCfg.reply_msgs:
        AndroidRPC().sms_send(msg['address'], reply_body)


class Msg(BaseModel):
    msg: str
    msg_from: Optional[str] = None
    msg_type: Optional[str] = None
    auth_token: str


notifications_recv = []
@app.post("/alarm/notification/")
async def alarm_notification(msg: Msg):
    if msg.auth_token != CMDS_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect request token",
        )
    results = []
    errors = []
    notifications_recv.append(msg)
    if not AlarmCfg.enabled:
        return dict(result='alarm disabled')
    for p in AlarmCfg.notified_phones:
        r = AndroidRPC().sms_send(p, msg.msg)
        if r.get('error'):
            errors.append(r)
        else:
            results.append(r)
        if 'This is a test mail send by your NVR' in msg:
            break
    msg.auth_token = None
    return dict(result=results, error=errors)


@app.get("/alarm/notifications/")
async def alarm_notifications(current_user: User = Depends(get_current_active_user)):
    return dict(notifications=[m.msg for m in notifications_recv],
                sms=[m['body'] for m in sms_rcv['msgs']])


@app.post("/alarm/activate/")
async def alarm_activate(current_user: User = Depends(get_current_active_user)):
    return dict(result='activated')


@app.get("/alarm/status/")
async def alarm_status(current_user: User = Depends(get_current_active_user)):
    return dict(result='activated')


@app.post("/alarm/reset/")
async def alarm_reset(current_user: User = Depends(get_current_active_user)):
    return dict(result='resetted')


if __name__ == '__main__':
    uvicorn.run(app, host=CMDS_SERVER, port=CMDS_SERVER_PORT, workers=1)

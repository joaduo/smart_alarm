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


FULL_PHONE_LENGTH_WITH_PLUS = int(os.environ.get('LOCAL_PHONES_LENGTH','13')) # Eg: len(+015555551234)
LOCAL_PHONES_PREFIX = os.environ.get('LOCAL_PHONES_PREFIX','') #Eg: '+01555'
def normalize_phone(p):
    full = FULL_PHONE_LENGTH_WITH_PLUS
    p = p.strip()
    #+54 2615 9639 94
    if len(p) < full:
        p = LOCAL_PHONES_PREFIX[:full - len(p)] + p
    return p

def split_phones(phones_str):
    return set(normalize_phone(p) for p in phones_str.strip().split(',') if p.strip())

def remove_phone_prefix(s):
    pref = LOCAL_PHONES_PREFIX
    if s.startswith(pref):
        return s[len(pref):]
    return s

def phones_to_str(phone_group):
    return ','.join(remove_phone_prefix(p) for p in sorted(phone_group))

SMS_CHECK_SECONDS=int(os.environ.get('SMS_CHECK_SECONDS', '5'))
CMDS_SERVER = os.environ.get('CMDS_SERVER', '127.0.0.1')
CMDS_SERVER_PORT = int(os.environ.get('CMDS_SERVER_PORT', '8000'))
CMDS_AUTH_TOKEN= os.environ.get('CMDS_AUTH_TOKEN')
ALARM_NOTIFIED_PHONES = split_phones(os.environ.get('ALARM_NOTIFIED_PHONES', ''))
ALARM_USER_PHONES = split_phones(os.environ.get('ALARM_USER_PHONES', ''))
ALARM_ADMIN_PHONES = split_phones(os.environ.get('ALARM_ADMIN_PHONES', ''))

assert CMDS_AUTH_TOKEN

class AlarmCfg:
    notified_phones = ALARM_NOTIFIED_PHONES.copy()
    user_phones = ALARM_USER_PHONES.copy()
    admin_phones = ALARM_ADMIN_PHONES.copy()
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


USER_HELP='''
HELP
ON
OFF
STATUS'''
ADMIN_HELP='''
ON n
OFF n
ADD n
RM n
ADDADMIN n
RMADMIN n'''
def process_cmd(msg, reply=None):
    # msg = {'read': '0', 'body': 'Tes',     '_id': '4', 'date': '1610213710004', 'address': '+1...'}
    reply = reply or reply_msg
    cmd = msg.get('body')
    cmd = cmd.upper()
    from_phone = normalize_phone(msg.get('address'))
    is_admin = from_phone in AlarmCfg.admin_phones
    is_user = is_admin or from_phone in AlarmCfg.user_phones
    if is_admin:
        admin_cmds(cmd, from_phone, msg, reply)
    if is_user:
        user_cmds(cmd, from_phone, msg, is_admin, reply)
    else:
        logger.info(f'Unknown sender {msg}')


def reply_msg(msg, reply_body):
    if AlarmCfg.reply_msgs:
        logger.info(f'Replying {msg} with {reply_body!r}')
        AndroidRPC().sms_send(msg['address'], reply_body)


def admin_cmds(cmd, from_phone, msg, reply):
    match = lambda exp: cmd.startswith(exp)
    if match('ADDADMIN'):
        phones = split_phones(cmd.split(maxsplit=1)[1])
        AlarmCfg.admin_phones.update(phones)
        reply(msg, f'Adding admin {phones_to_str(phones)}')
    elif match('RMADMIN'):
        phones = split_phones(cmd.split(maxsplit=1)[1])
        AlarmCfg.admin_phones.difference_update(phones)
        reply(msg, f'Removing admin {phones_to_str(phones)}')
    elif match('ADD '):
        phones = split_phones(cmd.split(maxsplit=1)[1])
        AlarmCfg.user_phones.update(phones)
        AlarmCfg.notified_phones.update(phones)
        reply(msg, f'Adding user {phones_to_str(phones)}')
    elif match('RM '):
        phones = split_phones(cmd.split(maxsplit=1)[1])
        AlarmCfg.user_phones.difference_update(phones)
        AlarmCfg.notified_phones.difference_update(phones)
        reply(msg, f'Removing user {phones_to_str(phones)}')
    elif match('ON '):
        phones = set(split_phones(cmd.split(maxsplit=1)[1]))
        phones = phones & (AlarmCfg.user_phones | AlarmCfg.admin_phones)
        AlarmCfg.notified_phones.update(phones)
        reply(msg, f'Notifying users {phones_to_str(phones)}')
    elif match('OFF '):
        phones = set(split_phones(cmd.split(maxsplit=1)[1]))
        phones = phones & (AlarmCfg.user_phones | AlarmCfg.admin_phones)
        AlarmCfg.notified_phones.difference_update(phones)
        reply(msg, f'Not notifying {phones_to_str(phones)}')


def user_cmds(cmd, from_phone, msg, is_admin, reply):
    match = lambda exp: cmd.strip() == exp
    if match('STATUS'):
        # TODO: check if NVR + cameras are online + etc
        if is_admin:
            reply(msg, build_status())
        else:
            reply(msg, f'Notified={from_phone in AlarmCfg.notified_phones}')
    elif match('ON'):
        AlarmCfg.notified_phones.add(from_phone)
        reply(msg, 'Notifications ON')
    elif match('OFF'):
        AlarmCfg.notified_phones.remove(from_phone)
        reply(msg, 'Notifications OFF')
    elif match('HELP') or not is_admin:
        # Print help if we can't match any command
        if is_admin:
            reply(msg, USER_HELP + ADMIN_HELP)
        else:
            reply(msg, USER_HELP)


def build_status():
    admin = phones_to_str(AlarmCfg.admin_phones)
    user = phones_to_str(AlarmCfg.user_phones)
    notify = phones_to_str(AlarmCfg.notified_phones)
    return f'Admins[{admin}]\nUser[{user}]\nNotify[{notify}]'


class FakeSMS(BaseModel):
    #{'read': '0', 'body': '', '_id': '28', 'date': '1610248992023', 'address': '+01...'}
    body: str
    address: str
    date: str


@app.post("/alarm/fakesms/")
async def alarm_fakesms(sms: FakeSMS, current_user: User = Depends(get_current_active_user)):
    replies = []
    def gather_msgs(msg, reply_msg):
        replies.append(reply_msg)
    process_cmd(dict(body=sms.body, address=sms.address, date=sms.date),
                reply=gather_msgs)
    return replies


class Notification(BaseModel):
    msg: str
    msg_from: Optional[str] = None
    msg_type: Optional[str] = None
    auth_token: str


notifications_recv = []
@app.post("/alarm/notification/")
async def alarm_notification(notification: Notification):
    if notification.auth_token != CMDS_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect request token",
        )
    results = []
    errors = []
    notifications_recv.append(notification)
    for p in AlarmCfg.notified_phones:
        r = AndroidRPC().sms_send(p, notification.msg)
        if r.get('error'):
            errors.append(r)
        else:
            results.append(r)
        if 'This is a test mail send by your NVR' in notification:
            break
    notification.auth_token = None
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

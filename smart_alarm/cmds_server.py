"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel
import logging
from smart_alarm.cmds_server_helper import User, get_current_active_user, app,\
    AndroidRPC
from fastapi_utils.tasks import repeat_every
import json
import uvicorn
from smart_alarm.cmds_commands import network_status_report, reboot_android,\
    tempature_report, ipcam_shot_cmd
from smart_alarm.solve_settings import solve_settings
from smart_alarm.phone_numbers import phones_to_str, split_phones,\
    normalize_phone, is_phone
import os

logger = logging.getLogger('cmds_server')

settings = solve_settings()

counter = 0
sms_rcv = dict(msgs=[], ids=set())
@app.on_event("startup")
@repeat_every(seconds=settings.sms_check_period, logger=logger, wait_first=True)
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
STATUS
SHOT c,c
REF c,c'''
ADMIN_HELP='''
ON n|p
OFF n|p
ADD p
ADDN n p
RM n|p
ADDADMIN n|p
RMADMIN n|p
CONFIG|CFG [N]umbers
SSH All
SSH Close
SSH Ip
KILL|K A|C|M
'''
def process_cmd(msg, reply=None):
    # msg = {'read': '0', 'body': 'Tes',     '_id': '4', 'date': '1610213710004', 'address': '+1...'}
    reply = reply or reply_message
    cmd = msg.get('body')
    from_phone = normalize_phone(msg.get('address'))
    is_admin = from_phone in settings.admins
    is_user = is_admin or from_phone in settings.users
    if is_admin:
        admin_cmds(cmd, from_phone, msg, reply)
    if is_user:
        user_cmds(cmd, from_phone, msg, is_admin, reply)
    else:
        logger.info(f'Unknown sender {msg}')


def reply_message(msg, reply_body):
    if settings.reply_messages:
        logger.info(f'Replying {msg} with {reply_body!r}')
        for i in range(settings.split_max_sms):
            part = reply_body[i*160:(i+1)*160]
            if not part:
                break
            AndroidRPC().sms_send(msg['address'], reply_body)


def admin_cmds(cmd, from_phone, msg, reply):
    match = lambda exp: cmd.upper().startswith(exp)
    args = cmd.split(maxsplit=1)
    if match('ADDADMIN'):
        phones = split_phones(args[1])
        settings.admins.update(phones)
        reply(msg, config_report())
    elif match('RMADMIN'):
        phones = split_phones(args[1])
        settings.admins.difference_update(phones)
        reply(msg, config_report())
    elif match('ADDN '):
        args = args[1].split()
        name = args[0]
        phone = args[1]
        if is_phone(name):
            name = phone
            phone = args[0]
        phone = normalize_phone(phone)
        settings.users.add(phone)
        settings.names_to_phones[name.lower()] = phone
        reply(msg, config_report())
    elif match('ADD '):
        phones = split_phones(args[1])
        settings.users.update(phones)
        reply(msg, config_report())
    elif match('RM '):
        phones = split_phones(args[1])
        settings.users.difference_update(phones)
        settings.notified_users.difference_update(phones)
        reply(msg, config_report())
    elif match('ON '):
        phones = split_phones(args[1])
        phones = phones & (settings.users | settings.admins)
        settings.notified_users.update(phones)
        reply(msg, config_report())
    elif match('OFF '):
        phones = split_phones(args[1])
        phones = phones & (settings.users | settings.admins)
        settings.notified_users.difference_update(phones)
        reply(msg, config_report())
    elif match('CFG') or match('CONFIG'):
        as_numbers = len(args) > 1
        reply(msg, config_report(names=not as_numbers))
    elif match('KILL ') or match('K '):
        server = args[1][0].upper()
        if server == 'A':
            r = AndroidRPC().kill_android_server()
            reply(msg, f'{r["result"].get("result") or r}')
    elif match('BOOT '):
        server = args[1][0].upper()
        if server == 'A':
            reply(msg, f'Rebooting android...')
            r = reboot_android()
        if server == 'C':
            os._exit(1)
        #elif server == 'C':
        #    reply(msg, f'Killing http_server')
#     elif match('SSH'):
#         ipre = r'(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])'
#         if match('SSH A'): # ssh all
#             pass
#         elif match('SSH C'): # ssh close
#             pass
#         elif re.search(ipre, cmd[len('SSH'):].strip()):
#             pass


def user_cmds(cmd, from_phone, msg, is_admin, reply):
    cmd = cmd.strip()
    args = cmd.split(maxsplit=1)
    match = lambda exp: cmd.upper() == exp
    if match('STATUS'):
        text = f'Notified:{from_phone in settings.notified_users}\n'
        text += network_status_report() + '\n'
        text += tempature_report()
        reply(msg, text)
    elif match('ON'):
        settings.notified_users.add(from_phone)
        reply(msg, 'Notifications ON')
    elif match('OFF'):
        settings.notified_users.remove(from_phone)
        reply(msg, 'Notifications OFF')
    elif cmd.upper().startswith('SH'):
        do_shots(msg, args, reply)
    elif cmd.upper().startswith('REF'):
        do_shots(msg, args, reply, prefix='_ref')
    elif match('HELP') or not is_admin:
        # Print help if we can't match any user command
        if is_admin:
            reply(msg, USER_HELP + ADMIN_HELP)
        else:
            reply(msg, USER_HELP)


def do_shots(msg, args, reply, prefix=''):
    cameras = args[1] if len(args) > 1 else None
    imgs = ipcam_shot_cmd(cameras, upload=True, prefix=prefix)
    text = ''
    for img in imgs['urls']:
        text += f'{img}\n'
    for num, error in imgs['errors']:
        text += f'{num} error:{error[:20]}\n'
    text += '\nhttps://a.jduo.de'
    reply(msg, text)


def config_report(names=True):
    admin = phones_to_str(settings.admins, names)
    user = phones_to_str(settings.users, names)
    notify = phones_to_str(settings.notified_users, names)
    return f'Admins:{admin}\nUser:{user}\nNotify:{notify}'


class FakeSMS(BaseModel):
    #{'read': '0', 'body': '', '_id': '28', 'date': '1610248992023', 'address': '+01...'}
    body: str
    address: str
    date: str


@app.post("/alarm/fakesms/")
async def alarm_fakesms(sms: FakeSMS, current_user: User = Depends(get_current_active_user)):
    replies = []
    def gather_msgs(msg, reply_message):
        replies.append(reply_message)
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
    if notification.auth_token != settings.http_server_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect request token",
        )
    results = []
    errors = []
    notifications_recv.append(notification)
    for p in settings.notified_users:
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


if __name__ == '__main__':
    logger = logging.getLogger('cmds_server')
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    logging.info(config_report())
    uvicorn.run(app, host=settings.http_server_address,
                port=settings.http_server_port, workers=1)

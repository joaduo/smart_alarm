"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import logging
import os
from typing import Optional
import json
import time
import secrets
import asyncio
import re
from collections import defaultdict
from datetime import datetime

from pydantic import BaseModel
import uvicorn
from fastapi import Depends, HTTPException, status
from fastapi_utils.tasks import repeat_every

from smart_alarm.cmds_server_base import User, get_current_active_user, app,\
    AndroidRPC
from smart_alarm.cmds_commands import network_status_report, reboot_android,\
    tempature_report, gather_ipcam_shots, android_shot_cmd, delete_previous_s3_files,\
    smart_split, manage_ssh, clean_ufw_status, SirenRelay
from smart_alarm.solve_settings import solve_settings
from smart_alarm.phone_numbers import phones_to_str, split_phones,\
    normalize_phone, is_phone
from smart_alarm.utils import async_thread


logger = logging.getLogger('cmds_server')

settings = solve_settings()

counter = 0
sms_rcv = dict(msgs=[], ids=set())
@app.on_event("startup")
@repeat_every(seconds=settings.sms_check_period, logger=logger, wait_first=True)
async def periodic_sms_check():
    msgs = AndroidRPC(max_tries=1).sms_get_messages(unread=True)
    if msgs.get('error'):
        logger.error(f'While checking incoming SMS: {msgs}')
        return
    new_messages = set()
    for m in msgs['result']['rpc_result']['result']:
        if m['_id'] not in sms_rcv['ids']:
            new_messages.add(m['_id'])
            sms_rcv['ids'].add(m['_id'])
            sms_rcv['msgs'].append(m)
            try:
                await process_cmd(m)
            except Exception as e:
                logger.exception(f'While processing {m}')
                e = str(e)[:110]
                reply_message(m, f'Exception processing your message {e}')
    if new_messages:
        AndroidRPC().smsMarkMessageRead(list(new_messages),True)
        with open('msgs.json', 'w') as fp:
            json.dump(sms_rcv['msgs'], fp, indent=1)


previous_report = ''
@app.on_event("startup")
@repeat_every(seconds=settings.status_check_period, logger=logger, wait_first=True)
async def periodic_status_check():
    global previous_report
    wait_sec = 5
    report = network_status_report(timeout=wait_sec, internet=False)
    if not previous_report:
        previous_report = report
        return
    if previous_report != report:
        histogram = defaultdict(int)
        histogram[report] += 1
        for _ in range(settings.status_attempts - 1):
            time.sleep(wait_sec)
            # We don't want to check internet, ip changes from time to time
            report = network_status_report(timeout=wait_sec, internet=False)
            histogram[report] += 1
        # We want the most popular report
        report = list(sorted((count, rep) for rep,count in histogram.items()))[-1][1]
    if previous_report != report:
        logger.info(f'Status change, notifying {report}...')
        for phone in settings.admins & settings.notified_users:
            AndroidRPC().sms_send(phone, report)
    else:
        logger.debug('No status change')
    previous_report = report


USER_HELP='''
ON
OFF
PANIC [secs]

SHOT c,c
REF c,c

HELP
STATUS
'''
ADMIN_HELP='''
ON n|p
OFF n|p
ADD p
ADDN n p
RM n|p
ADDADMIN n|p
RMADMIN n|p
PW
CFG [N]
SSHO|C [any|Ip]
KILL A|C
BOOT A
AUTOSHOT On|Off
SIREN On|Off
'''
async def process_cmd(msg, reply=None):
    # msg = {'read': '0', 'body': 'Tes',     '_id': '4', 'date': '1610213710004', 'address': '+1...'}
    reply = reply or reply_message
    cmd = msg.get('body')
    from_phone = normalize_phone(msg.get('address'))
    is_admin = from_phone in settings.admins
    is_user = is_admin or (from_phone in settings.users)
    if is_admin:
        admin_cmds(cmd, from_phone, msg, reply)
    if is_user:
        await user_cmds(cmd, from_phone, msg, is_admin, reply)
    else:
        logger.info(f'Unknown sender {msg}')


def reply_message(msg, reply_body):
    if settings.reply_messages:
        logger.info(f'Replying {msg} with {reply_body!r}')
        max_chars = settings.split_max_chars_per_sms
        for i in range(settings.split_max_sms):
            part = reply_body[i*max_chars:(i+1)*max_chars]
            if not part:
                break
            if i:
                time.sleep(settings.split_sms_wait_sec)
            AndroidRPC().sms_send(msg['address'], part)


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
        args = smart_split(args[1])
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
    elif match('KILL '):
        server = args[1][0].upper()
        if server == 'A':
            r = AndroidRPC().kill_android_server()
            reply(msg, f'{r["result"].get("result") or r}')
        if server == 'C':
            reply(msg, f'Killing http_server')
            os._exit(1)
    elif match('PW'):
        delete_previous_s3_files()
        settings.web_auth_token = secrets.token_urlsafe(settings.web_auth_token_size)
        reply(msg, f'Token rotated {build_client_url()}')
    elif match('BOOT '):
        server = args[1][0].upper()
        if server == 'A':
            reply(msg, f'Rebooting android...')
            r = reboot_android()
    elif match('SSH'):
        ipre = r'(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])'
        valid_ip = lambda: re.search(ipre, args[1].strip()) and args[1]
        if match('SSHO'): # ssh all
            ip =  valid_ip() if len(args) > 1 else 'any'
            if ip:
                out = manage_ssh(ip, action='open')
                reply(msg, out)
        elif match('SSHC'): # ssh close
            ip =  valid_ip() if len(args) > 1 else 'any'
            if ip:
                out = manage_ssh(ip, action='close')
                reply(msg, out)
        elif match('SSHS'): # Status printing
            out = manage_ssh('any', action='status')
            reply(msg, clean_ufw_status(out))


async def user_cmds(cmd, from_phone, msg, is_admin, reply):
    cmd = cmd.strip()
    args = cmd.split(maxsplit=1)
    args = args[1].strip() if len(args) > 1 else None
    match = lambda exp: cmd.upper() == exp
    startswith = lambda exp: cmd.upper().startswith(exp)
    if match('STATUS'):
        text = f'Notified:{from_phone in settings.notified_users}\n'
        text += network_status_report() + '\n'
        text += tempature_report()
        reply(msg, text)
    elif match('ON'):
        settings.notified_users.add(from_phone)
        settings.shot_on_motion = True
        settings.siren_on = True
        reply(msg, 'Alarm ON')
    elif match('OFF'):
        settings.notified_users.remove(from_phone)
        settings.shot_on_motion = False
        settings.siren_on = False
        reply(msg, 'Alarm OFF')
    elif startswith('SIREN'):
        flag = not settings.siren_on
        if args:
            if args.lower().startswith('on'):
                flag = True
            else:
                flag = False
        settings.siren_on = flag
        if not flag:
            siren.relay.off()
        reply(msg, f'Siren {"ON" if settings.siren_on else "OFF"}')
    elif startswith('HD'):
        if not args or args and args.upper() == 'ON':
            settings.ipcam_stream_path_current = settings.ipcam_stream_path_hd
            reply(msg, 'HD on')
        else:
            settings.ipcam_stream_path_current = settings.ipcam_stream_path_sub
            reply(msg, 'HD off')
    elif startswith('AUTOSH'):
        flag = not settings.shot_on_motion
        if args:
            if args.lower().startswith('on'):
                flag = True
            else:
                flag = False
        settings.shot_on_motion = flag
        reply(msg, f'Autoshot {"ON" if settings.shot_on_motion else "OFF"}')
    elif startswith('SH'):
        await do_shots(msg, args, reply)
    elif startswith('REF'):
        await do_shots(msg, args, reply, prefix='_ref')
    elif startswith('PANIC') or startswith('ALARM') or startswith('FIRE'):
        timeout = settings.siren_timeout_sec
        if args:
            try:
                timeout = int(args)
            except ValueError:
                pass
        siren.trigger_alarm(timeout, force=True)
        reply(msg, f'Triggered for {timeout} secs')
    elif match('HELP') or not is_admin:
        # Print help if we can't match any user command
        if is_admin:
            reply(msg, USER_HELP.replace('\nON\nOFF\n', '') + ADMIN_HELP)
        else:
            reply(msg, USER_HELP)


async def do_shots(msg, cameras, reply, prefix=''):
    text = await _do_shots(cameras, prefix)
    reply(msg, text)


async def _do_shots(cameras=None, prefix=''):
    with async_thread.thread_pool(5):
        tasks = gather_ipcam_shots(cameras, upload=True, prefix=prefix, stream_path=settings.ipcam_stream_path_current)
        task = android_shot_cmd.as_task(cameras, upload=True, prefix=prefix)
        newtasks = [t for _,t in tasks] + [task]
        results = await asyncio.gather(*newtasks)
    text = build_client_url() +'\n'
    for i,e in list(zip([i for i,_ in tasks], results)):
        if e:
            text += f'{i}:{e[:10]}\n'
        else:
            text += f'{i}:ok\n'
    if results[-1]['errors']:
        text += f'and:{str(results[-1]["errors"])[:10]}\n'
    elif results[-1]['imgs']:
        text += 'and:ok\n'
    return text


def build_client_url():
    return f'https://{settings.s3_bucket}/w#{settings.web_auth_token}'


def config_report(names=True):
    admin = phones_to_str(settings.admins, names)
    user = phones_to_str(settings.users, names)
    notify = phones_to_str(settings.notified_users, names)
    return (f'Admins:{admin}\nUser:{user}\nNotify:{notify}\nHD:{int(settings.ipcam_stream_path_current == settings.ipcam_stream_path_hd)}\n'
            f'Siren:{int(settings.siren_on)}\nAutoshot:{int(settings.shot_on_motion)}')


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
    await process_cmd(dict(body=sms.body, address=sms.address, date=sms.date),
                      reply=gather_msgs)
    return replies


class Notification(BaseModel):
    msg: str
    msg_from: Optional[str] = None
    msg_type: Optional[str] = None
    auth_token: str


latest_shots = None
notifications_recv = []
siren = SirenRelay()
@app.post("/alarm/notification/")
async def alarm_notification(notification: Notification):
    if notification.auth_token != settings.http_server_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect request token",
        )
    notification.auth_token = None
    results = []
    errors = []
    now = datetime.utcnow()
    msg = notification.msg
    triggered = False
    global latest_shots
    if (settings.shot_on_motion
        and (not latest_shots
             or (now - latest_shots).total_seconds() > settings.siren_timeout_sec)):
        latest_shots = now
        if notification.msg_type == 'PIR':
            # Give it a 2 seconds gap to wait for an new event
            triggered = siren.trigger_alarm(timeout=settings.siren_timeout_sec + 2)
        msg += f'\nSiren: {"Triggered" if triggered else "Off"}\n'
        msg += await _do_shots()
    notifications_recv.append((notification, now, triggered))
    for p in settings.notified_users:
        r = AndroidRPC().sms_send(p, msg)
        if r.get('error'):
            errors.append(r)
        else:
            results.append(r)
        if 'This is a test mail send by your NVR' in notification:
            break
    return dict(result=results, error=errors)


@app.get("/alarm/notifications/")
async def alarm_notifications(current_user: User = Depends(get_current_active_user)):
    return dict(notifications=[f'{m.msg}:{ts}:{trg}' for m,ts,trg in notifications_recv],
                sms=[m['body'] for m in sms_rcv['msgs']])


if __name__ == '__main__':
    logger = logging.getLogger('cmds_server')
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    logging.info(config_report())
    settings.web_auth_token = secrets.token_urlsafe(settings.web_auth_token_size)
    delete_previous_s3_files()
    uvicorn.run(app, host=settings.http_server_address,
                port=settings.http_server_port, workers=1)

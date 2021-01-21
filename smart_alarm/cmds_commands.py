"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import requests
import subprocess
import logging
import random
import time

from contextlib import contextmanager
from smart_alarm.solve_settings import solve_settings

logger = logging.getLogger('cmds_commands')
settings = solve_settings()


@contextmanager
def timer():
    try:
        d=dict(start=time.time())
        yield d
    finally:
        end=time.time()
        d.update(end=end, delta=end-d['start'])


def ipcam_shot_cmd(cameras=None, upload=False, prefix=''):
    selected = set(smart_split(cameras))
    imgs = []
    errors = []
    for num, (ip, name) in settings.cameras_map.items():
        if (not selected
        or str(num) in selected
        or name in selected
        or name[0] in selected):
            i = f'{num}_{name}{prefix}.jpg'
            with timer() as timershot:
                error =  ipcam_shot(ip, i, upload)
            if not error:
                imgs.append((i, timershot.get('delta')))
            else:
                errors.append((num, error))
    return dict(urls=[f'https://a.jduo.de/i/{i}' for i,_ in imgs],
                deltas=[d for _,d in imgs],
                errors=errors)


def smart_split(joint_str):
    '''
    Split string from CLI arguments. (split by spaces and/or commas)
    So you can do
        --words "foo bar"
        --words foo,bar
        --words "foo,bar baz"
    '''
    if not joint_str or not joint_str.strip():
        return []
    joint_str = joint_str.strip()
    return [s2 for s1 in joint_str.split() for s2 in s1.split(',')]


def ipcam_shot(ip, shot_path, upload=False):
    upload = '1' if not upload else ''
    cmd = f'salarm_ipcam_shot rtsp://{settings.ipcam_user}:{settings.ipcam_password}@{ip}/videoSub {shot_path} {upload}'
    logging.info(f'Running:{cmd}')
    p, out, err = run_command(cmd.split())
    if p.returncode:
        return (out + err).decode('utf8')


def tempature_report():
    p, out, err = run_command('salarm_temperature'.split())
    if not p.returncode:
        return out.decode('utf8').strip()
    return (out + err).decode('utf8')


def network_status_report(timeout=2):
    result = gather_pings(timeout)
    report = ''
    for k,v in result.items():
        report += f'{k}:{v}\n'
    ip = test_internet(timeout) or ''
    report += f'ip:{ip}\n'
    report += f'andr:' + check_android()
    return report


def gather_pings(timeout=2):
    result = {}
    for k,v in settings.network_pings.items():
        if isinstance(v, list):
            count = 0
            for ip in v:
                if ping(ip, timeout):
                    count += 1
            result[k] = f'{count}/{len(v)}'
        else:
            result[k] = 'U' if ping(v, timeout) else 'D'
    return result


def check_android():
    #https://stackoverflow.com/questions/3634041/detect-when-android-emulator-is-fully-booted
    #adb shell getprop init.svc.bootanim
    p, out, err = run_command('adb shell getprop init.svc.bootanim'.split())
    out = out.decode('utf8')
    #'running'
    if out == 'stopped\r\n':
        return 'Up'
    if out == 'running\r\n':
        return 'Boot'
    return out


def reboot_android():
    p, out, err = run_command('adb shell reboot -p'.split())
    out = (out + err).decode('utf8')
    return out


def ping(host, timeout=2):
    """
    #https://stackoverflow.com/questions/2953462/pinging-servers-in-python
    Returns True if host (str) responds to a ping request.
    :param host: ip or hostname
    :param timeout: in seconds, may be decimal eg: 0.5
    """
    command = ['ping', '-c', '1', '-W', str(timeout), host]
    p, _, _ = run_command(command)
    return p.returncode == 0


def run_command(command):
    logger.debug('Running: %r' % command)
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    logger.debug('out: %r\nerr:%r', out, err)
    return p, out, err


ip_servers = [
    'https://ipapi.co/json/',
    'https://jsonip.com/',
    'https://api.ipify.org/?format=json',
    'https://ifconfig.co/json',
    ]
def test_internet(timeout=2):
    servers = ip_servers.copy()
    random.shuffle(servers)
    for s in servers:
        resp = get_myip(s, timeout)
        if resp:
            return resp['ip']


def get_myip(server, timeout=2):
    r = requests.get(server, timeout=timeout)
    try:
        return r.json()
    except Exception as e:
        return None

if __name__ == '__main__':
#     print(check_android())
#     print(ping('192.168.2.105'))
#     print(ping('192.168.2.4'))
    print(network_status_report())
    print(ipcam_shot('192.168.2.2', 'test.jpg'))
#     print(gather_pings())
#     print(test_internet())

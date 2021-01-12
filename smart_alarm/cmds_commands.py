"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import requests
import subprocess

import logging
import os
import random

logger = logging.getLogger('status_report')


def network_status_report(timeout=2):
    result = gather_pings(timeout)
    report = ''
    for k,v in result.items():
        report += f'{k}:{v}\n'
    ip = test_internet(timeout) or ''
    report += f'ip:{ip}\n'
    report += f'andr:' + check_android()
    return report


ALARM_NETWORK_PINGS = eval(os.environ.get('ALARM_NETWORK_PINGS', '{}'))
def gather_pings(timeout=2):
    result = {}
    for k,v in ALARM_NETWORK_PINGS.items():
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
#     print(gather_pings())
#     print(test_internet())

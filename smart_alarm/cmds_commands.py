"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import requests
import subprocess
import logging
import random
import threading
import time
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError
import gpiozero

from contextlib import contextmanager
from smart_alarm.solve_settings import solve_settings
from smart_alarm.cmds_server_base import AndroidRPC
import os
import re
from smart_alarm.utils import async_thread
from datetime import datetime


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


def upload_file(file_name, s3_path, content_type='image/jpeg', cache_control='private'):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # Upload the file
    s3_client = boto3.client('s3')
    parsed = urlparse(s3_path)
    try:
        s3_client.upload_file(file_name, parsed.netloc, parsed.path.strip('/'),
                              ExtraArgs={'ACL' : 'public-read',
                                         'CacheControl' : cache_control,
                                         'ContentType' : content_type})
    except ClientError as e:
        return str(e)


def delete_previous_s3_files():
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(settings.s3_bucket)
    return bucket.objects.filter(Prefix=f'i/').delete()


def build_common_img_path(shot_path):
    return f'{settings.s3_bucket}/i/{settings.web_auth_token}/{os.path.basename(shot_path)}'


def build_https_img_path(shot_path):
    return f'https://{build_common_img_path(shot_path)}'


def build_s3_img_path(shot_path):
    return f's3://{build_common_img_path(shot_path)}'


@async_thread
def android_shot_cmd(cameras, upload=False, prefix='', auto_focus=True):
    selected = cameras and set(smart_split(cameras.lower()))
    imgs = []
    errors = []
    if not selected or set(['a','and','andr']) & selected:
        basename = f'android{prefix}.jpg'
        path = os.path.join(settings.android_shot_dir, basename)
        with light.context():
            resp = AndroidRPC().cameraCapturePicture(path,useAutoFocus=auto_focus)
        #{'result': {'rpc_result': {'error': None, 'id': 1, 'result': {'takePicture': True, 'autoFocus': False}}}}
        result = resp['result']['rpc_result']['result']
        if result['takePicture']:
            local_path = os.path.join(settings.temp_dir, basename)
            _, out, _ = run_command(f'adb pull {path} {local_path}'.split())
            if '1 file pulled.' in out:
                imgs.append(basename)
                _, out, err = run_command(f'adb shell rm {path}'.split())
                if out:
                    errors.append(out + err)
                if upload:
                    err = upload_file(local_path, build_s3_img_path(local_path))
                    if err:
                        errors.append(err)
            else:
                errors.append(out + err)
        else:
            errors.append('Could not take picture')
    return dict(imgs=imgs, errors=errors)


def gather_ipcam_shots(cameras=None, upload=False, prefix='', stream_path='videoSub'):
    selected = cameras and set(smart_split(cameras))
    tasks = []
    for num, (ip, name) in settings.cameras_map.items():
        if (not selected
        or str(num) in selected
        or name in selected
        or name[0] in selected):
            i = f'{num}_{name}{prefix}.jpg'
            t = ipcam_shot.as_task(ip, i, stream_path, upload)
            tasks.append((num, t))
    return tasks


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


@async_thread
def ipcam_shot(ip, shot_path, stream_path, upload=False):
    if not ping(ip, timeout=3): #Make sure the ip cam is up
        return 'Ip Down'
    s3_path = build_s3_img_path(shot_path)
    cmd = f'salarm_ipcam_shot rtsp://{settings.ipcam_user}:{settings.ipcam_password}@{ip}/{stream_path} {shot_path} {upload} {s3_path}'
    logging.info(f'Running:{cmd}')
    p, out, err = run_command(cmd.split())
    if p.returncode:
        return out + err


def tempature_report():
    p, out, err = run_command('salarm_temperature'.split())
    if not p.returncode:
        return out.strip()
    return out + err


def network_status_report(timeout=2, internet=True):
    result = gather_pings(timeout)
    report = ''
    for k,v in result.items():
        report += f'{k}:{v}\n'
    if internet:
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
    _, out, _ = run_command('adb shell getprop init.svc.bootanim'.split())
    #'running'
    if out == 'stopped\r\n':
        return 'Up'
    if out == 'running\r\n':
        return 'Boot'
    return out


def reboot_android():
    p, out, err = run_command('adb shell reboot -p'.split())
    return out + err


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
    return p, out.decode('utf8'), err.decode('utf8')


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
        try:
            resp = get_myip(s, timeout)
            if resp:
                return resp['ip']
        except:
            logging.exception('While getting my ip')


def get_myip(server, timeout=2):
    r = requests.get(server, timeout=timeout)
    try:
        return r.json()
    except Exception as e:
        return None


def upload_web_client():
    path = os.path.join(os.path.dirname(__file__), 'client.html')
    logger.error(upload_file(path, 's3://a.jduo.de/w', content_type='text/html', cache_control='max-age=36000'))


def manage_ssh(ip, action='open'):
    _, out, err = run_command(f'sudo salarm_open_port {ip} {action}'.split())
    return out + err


def clean_ufw_status(out):
    '''
    Status: active
    Logging: on (low)
    Default: deny (incoming), allow (outgoing), disabled (routed)
    New profiles: skip
    
    To                         Action      From
    --                         ------      ----
    22/tcp                     ALLOW IN    192.168.200.104            # Smart Alarm allow incoming SSH for 192.168.200.104
    8000/tcp                   ALLOW IN    192.168.200.104            # Smart Alarm allow incoming SSH for 192.168.200.104
    22/tcp                     ALLOW IN    Anywhere                   # Smart Alarm allow incoming SSH for any
    22/tcp (v6)                ALLOW IN    Anywhere (v6)              # Smart Alarm allow incoming SSH for any
    '''
    newout = []
    for l in out.splitlines():
        if ('Logging:' in l
            or 'New profiles:' in l
            or '------' in l
            or 'Action' in l
            or not l.strip()):
            continue
        l = l.replace('Default: ','')
        l = re.sub('\s+', ' ', l)
        l = re.sub('#\s.*$', '', l).strip()
        newout.append(l)
    return '\n'.join(newout)


class SirenRelay:
    def __init__(self, pin=None):
        self.pin = settings.siren_pin_number if pin is None else pin
        self.relay = gpiozero.OutputDevice(self.pin, active_high=False, initial_value=False)
        self.latest_trigger = None

    def trigger_siren(self, timeout:int=125, force:bool=False):
        if not force and not solve_settings().siren_on:
            return False
        assert timeout, 'Please provide a timeout'
        now = datetime.utcnow()
        self.latest_trigger = now
        self.relay.on()
        def turn_off():
            time.sleep(timeout)
            if self.latest_trigger == now:
                self.relay.off()
        threading.Thread(target=turn_off).start()
        return True


class LightRelay:
    def __init__(self, pin=None):
        self.pin = settings.light_pin_number if pin is None else pin
        self.relay = gpiozero.OutputDevice(self.pin, active_high=False, initial_value=False)
        self.latest_trigger = None

    @contextmanager
    def context(self):
        self.relay.on()
        try:
            yield self
        finally:
            self.relay.off()

    def turn_on(self, timeout:int=125):
        assert timeout, 'Please provide a timeout'
        now = datetime.utcnow()
        self.latest_trigger = now
        self.relay.on()
        def turn_off():
            time.sleep(timeout)
            if self.latest_trigger == now:
                self.relay.off()
        threading.Thread(target=turn_off).start()
        return True

siren = SirenRelay()
light = LightRelay()
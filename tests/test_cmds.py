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
from smart_alarm.cmds_server_helper import AndroidRPC
import os
from smart_alarm.cmds_commands import run_command, timer

logger = logging.getLogger('cmds_commands')
settings = solve_settings()

import boto3
from botocore.exceptions import ClientError


def upload_file(file_name, bucket, key=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # Upload the file
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(file_name, bucket, key, ExtraArgs={'ACL':'public-read',
                                                                 'CacheControl':'private',
                                                                 'ContentType':'image/jpeg '})
    except ClientError as e:
        return str(e)

def android_shot_cmd(upload=False, prefix='', auto_focus=True):
    path = os.path.join(settings.android_shot_dir, f'android{prefix}.jpg')
    with timer() as timershot:
        resp = AndroidRPC().cameraCapturePicture(path,useAutoFocus=auto_focus)
        #{'result': {'rpc_result': {'error': None, 'id': 1, 'result': {'takePicture': True, 'autoFocus': False}}}}
        result = resp['result']['rpc_result']['result']
    imgs = []
    errors = []
    if result['takePicture']:
        local_path = os.path.join(settings.temp_dir, f'android{prefix}.jpg')
        _, out, _ = run_command(f'adb pull {path} {local_path}'.split())
        if '1 file pulled.' in out:
            imgs.append((f'android{prefix}.jpg', timershot['delta']))
            _, out, err = run_command(f'adb shell rm {path}'.split())
            if out:
                errors.append(out + err)
            err = upload_file(local_path, 'a.jduo.de', f'i/android{prefix}.jpg')
            if err:
                errors.append(err)
        else:
            errors.append(out + err)
    else:
        errors.append('Could not take picture')
    return dict(urls=[f'https://a.jduo.de/i/{i}' for i,_ in imgs],
                deltas=[d for _,d in imgs],
                errors=errors)


def main():
    print(android_shot_cmd())




if __name__ == '__main__':
    main()

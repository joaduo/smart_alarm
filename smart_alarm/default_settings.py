# -*- coding: utf-8 -*-
'''
xpathwebdriver
Copyright (c) 2014 Juju. Inc

Code Licensed under MIT License. See LICENSE file.
'''
from smart_alarm.solve_settings import ConfigVar, BaseSettings, DeferParser
from smart_alarm import phone_numbers


class DefaultSettings(BaseSettings):
    phone_length = ConfigVar(
        doc='Full phone length Eg: 13 = len(+015555551234)',
        default=13)

    local_phone_prefix = ConfigVar(
        doc='Eg: +01555',
        default='',
        env_var='LOCAL_PHONES_PREFIX')

    sms_check_period = ConfigVar(
        doc='Period in seconds to check SMS',
        default=5,
        env_var='SMS_CHECK_SECONDS')

    status_check_period = ConfigVar(
        doc='Period in seconds to check Network status',
        default=60,
        env_var='STATUS_CHECK_SECONDS')

    status_attempts= ConfigVar(
        doc='Attempts of checking status',
        default=3,
        env_var='STATUS_CHECK_ATTEMPTS')

    reply_messages = ConfigVar(
        doc='Reply SMS messages',
        default=True)

    http_server_address = ConfigVar(
        doc='Address HTTP server should listen to',
        default='127.0.0.1',
        env_var='CMDS_SERVER')

    http_server_port = ConfigVar(
        doc='TCP for HTTP server',
        default=8000,
        env_var='CMDS_SERVER_PORT')

    http_server_token = ConfigVar(
        doc='Authentication token',
        default=None,
        env_var='CMDS_AUTH_TOKEN',
        parser=str,
        mandatory=True)

    names_to_phones = ConfigVar(
        doc='{"john":"2639230", "alice":"1234"}',
        default={},
        parser=eval,
        env_var='ALARM_PHONES_MAP')

    notified_users = ConfigVar(
        doc='Notified phones or names',
        default='',
        parser=DeferParser(phone_numbers.split_phones),
        env_var='ALARM_NOTIFIED_PHONES')

    users = ConfigVar(
        doc='User phones or names',
        default='',
        parser=DeferParser(phone_numbers.split_phones),
        env_var='ALARM_USER_PHONES')

    admins = ConfigVar(
        doc='Admin phones or names',
        default='',
        parser=DeferParser(phone_numbers.split_phones),
        env_var='ALARM_ADMIN_PHONES')

    ipcam_user = ConfigVar(
        doc='Ip Camera username',
        default='',
        env_var='SALARM_IPCAM_USER')

    ipcam_password = ConfigVar(
        doc='Ip Camera password',
        default='',
        env_var='SALARM_IPCAM_PASSWORD')

    network_pings = ConfigVar(
        doc='Network ping config',
        default='',
        parser=eval,
        env_var='ALARM_NETWORK_PINGS')

    cameras_map = ConfigVar(
        doc='Network ping config',
        default='',
        parser=eval,
        env_var='ALARM_CAMERAS_MAP')

    split_max_sms = ConfigVar(
        doc='Max amount of SMS to send per message',
        default=3,
        env_var='SALARM_SPLIT_MAX_SMS')
    
    split_max_chars_per_sms = ConfigVar(
        doc='Max amount of chars to send per SMS',
        default=150,
        env_var='SALARM_SPLIT_MAX_CHARS_PER_SMS')

    jwt_secret_key = ConfigVar(
        doc='JWT_SECRET_KEY use "openssl rand -hex 32"',
        mandatory=True,
        env_var='JWT_SECRET_KEY')

    jwt_algorithm = ConfigVar(
        doc='JWT_ALGORITHM',
        default='HS256',
        env_var='JWT_ALGORITHM')

    jwt_token_expire_minutes = ConfigVar(
        doc='JWT_ALGORITHM',
        default=1200,
        env_var='JWT_ACCESS_TOKEN_EXPIRE_MINUTES')

    android_server = ConfigVar(
        doc='ANDROID_SERVER',
        default='127.0.0.1',
        env_var='ANDROID_SERVER')

    android_server_port = ConfigVar(
        doc='ANDROID_SERVER_PORT',
        default=8001,
        env_var='ANDROID_SERVER_PORT')

    android_auth_token = ConfigVar(
        doc='ANDROID_AUTH_TOKEN',
        mandatory=True,
        env_var='ANDROID_AUTH_TOKEN')

    user_hashed_password = ConfigVar(
        doc='USER_HASHED_PASSWORD',
        mandatory=True,
        env_var='USER_HASHED_PASSWORD')

    temp_dir = ConfigVar(
        doc='TEMP_DIR',
        default='/tmp/',
        env_var='TEMP_DIR')

    android_shot_dir = ConfigVar(
        doc='ANDROID_SHOT_DIR',
        default='/sdcard/Download/',
        env_var='ANDROID_SHOT_DIR')

#     s3_images_path = ConfigVar(
#         doc=('S3 path like s3://my.domian/folder/images/'),
#         default='',
#         mandatory=True,
#         env_var='ALARM_S3_IMAGES_PATH')

    s3_bucket = ConfigVar(
        doc='',
        default='',
        env_var='ALARM_S3_BUCKET')

#     web_client_url = ConfigVar(
#         doc='',
#         default='https://example/myalarm/',
#         env_var='ALARM_WEB_CLIENT_URL')

    web_auth_token = ConfigVar(
        doc=('Unless set, it will be automatically set at startup.'
             ' Will be used to authenticate Web Client.'),
        default='',
        env_var='ALARM_WEB_AUTH_TOKEN')

    web_auth_token_size = ConfigVar(
        doc='Web Auth token size in bytes.',
        default=8,
        env_var='ALARM_WEB_AUTH_TOKEN_SIZE')


# Soon to be deprecated
Settings = DefaultSettings


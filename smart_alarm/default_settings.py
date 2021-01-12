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


# Soon to be deprecated
Settings = DefaultSettings


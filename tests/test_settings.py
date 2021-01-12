

import os
from smart_alarm.solve_settings import solve_settings




def main():
    os.environ['JWT_SECRET_KEY'] = '123'
    os.environ['ANDROID_AUTH_TOKEN'] = '123'

    os.environ['USER_HASHED_PASSWORD'] = '123'
    os.environ['ALARM_NOTIFIED_PHONES'] = '1234567,jane,unknown'
    os.environ['ALARM_ADMIN_PHONES'] = '1234569,joe2'
    os.environ['ALARM_USER_PHONES'] = ',jo'
    os.environ['LOCAL_PHONES_PREFIX'] = '+37000'
    
    os.environ['ALARM_PHONES_MAP'] = '''dict(
        joe=+370001234567,
        joe2=1234568,
        hanna=1234569,
        jane=1234560,
    )'''
    settings = solve_settings()
    for name in dir(settings._settings):
        if not name.startswith('_'):
            print(name, getattr(settings, name))


if __name__ == '__main__':
    main()

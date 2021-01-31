"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
import asyncio
import time
from pprint import pprint
from smart_alarm.utils import async_thread


@async_thread
def blocking_io(num):
    # File operations (such as logging) can block the
    # event loop: run them in a thread pool.
    with open('/dev/urandom', 'rb') as f:
        print(num)
        time.sleep(1)
        print(f'{num}:end')
        return f.read(100)


async def main():
    sync_r = blocking_io(0)
    print(sync_r)

    with blocking_io.thread_pool(10):
        tasks = []
        for i in range(10):
            t = blocking_io.as_task(num=i)
            print(f't:{t}')
            tasks.append(t)
        r = await asyncio.gather(*tasks)
        pprint(r)

    with async_thread.thread_pool():
        tasks = []
        for i in range(10):
            t = blocking_io.as_task(num=i)
            print(f't:{t}')
            tasks.append(t)
        with async_thread.thread_pool():
            tasks = []
            for i in range(10):
                t = blocking_io.as_task(num=i)
                print(f't:{t}')
                tasks.append(t)
            r = await asyncio.gather(*tasks)
            pprint(r)
        r = await asyncio.gather(*tasks)
        pprint(r)


if __name__ == '__main__':
    asyncio.run(main())

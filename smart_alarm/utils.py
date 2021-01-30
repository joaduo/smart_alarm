"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.

(Works on Python 2.7 too, for old Android devices)
"""
import asyncio
import concurrent.futures


class async_thread:
    pools = []
    def __init__(self, function):
        self.function = function

    def __call__(self, *args, **kwargs):
        return self.function(*args)

    @classmethod
    def push_pool(cls, pool): 
        cls.pools.append(pool)

    @classmethod
    def pop_pool(cls):
        return cls.pools.pop()

    @classmethod
    def get_pool(cls):
        assert cls.pools, f'Run this task in a pool context "with {cls}.thread_pool():..."'
        return cls.pools[-1]

    def as_task(self, *args, **kwargs):
        loop = asyncio.get_running_loop()
        # run_in_executor only allow *args
        return loop.run_in_executor(self.get_pool(),
                                    self._unpack_args_kwargs, args, kwargs)

    def _unpack_args_kwargs(self, args, kwargs):
        # Unpack arguments 
        return self.function(*args, **kwargs)

    @classmethod
    def thread_pool(cls, max_workers=3, *args, **kwargs):
        pool = concurrent.futures.ThreadPoolExecutor(max_workers, *args, **kwargs)
        cls.push_pool(pool)
        class PoolContext:
            def __enter__(self):
                return pool.__enter__()
            def __exit__(self, exc_type, exc_val, exc_tb):
                cls.pop_pool()
                return pool.__exit__(exc_type, exc_val, exc_tb)
        return PoolContext()


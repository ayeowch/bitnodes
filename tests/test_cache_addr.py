#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from binascii import unhexlify

from cache_addr import CacheAddr
from cache_addr import init_conf
from utils import new_redis_conn


def test_cache_addr():
    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..',
        'conf',
        'cache_addr.conf.default')
    init_conf(conf_filepath)

    redis_conn = new_redis_conn(db=1)

    pcap_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'data',
        'cache.pcap')
    cache = CacheAddr(
        pcap_filepath,
        magic_number=unhexlify('f9beb4d9'),
        redis_conn=redis_conn)

    cache.cache_messages()
    assert cache.count == 16581
    assert cache.addr_manager.count == 0

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from binascii import unhexlify
from unittest import mock

from cache_inv import CacheInv
from cache_inv import init_conf
from utils import new_redis_conn


@mock.patch('redis.StrictRedis')
def test_cache_inv(mock_strict_redis):
    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..',
        'conf',
        'cache_inv.conf.default')
    init_conf(conf_filepath)

    redis_conn = new_redis_conn(db=1)

    pcap_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'data',
        'cache.pcap')
    cache = CacheInv(
        pcap_filepath,
        magic_number=unhexlify('f9beb4d9'),
        redis_conn=redis_conn)

    cache.cache_messages()
    assert cache.count == 27796
    assert len(cache.invs.keys()) == 203

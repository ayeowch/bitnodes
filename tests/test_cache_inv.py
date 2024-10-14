#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from unittest import mock

from binascii import unhexlify

from cache_inv import CacheInv, init_conf
from utils import new_redis_conn


@mock.patch("redis.StrictRedis")
def test_cache_inv(mock_strict_redis):
    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "conf",
        "cache_inv.conf.default",
    )
    init_conf(conf_filepath)

    redis_conn = new_redis_conn(db=1)

    pcap_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cache.pcap"
    )
    cache = CacheInv(
        pcap_filepath, magic_number=unhexlify("f9beb4d9"), redis_conn=redis_conn
    )

    cache.cache_messages()
    assert len(cache.invs[1]) == 197
    assert len(cache.invs[2]) == 0
    assert sum([len(v) for v in cache.invs[1].values()]) == 27714

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from unittest import mock

from binascii import unhexlify

from cache_inv import CacheInv, CONF, init_conf
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

    CONF["blockhash_suffixes"] = set()

    CONF["inv_1_count"] = 10

    redis_conn = new_redis_conn(db=1)

    pcap_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cache.pcap"
    )
    exclude_src_addrs = {
        ("185.237.100.156", 12412),
        ("2604:2dc0:100:240f::1", 8333),
    }
    cache = CacheInv(
        pcap_filepath,
        exclude_src_addrs=exclude_src_addrs,
        magic_number=unhexlify("f9beb4d9"),
        redis_conn=redis_conn,
    )

    cache.cache_messages()

    assert len(cache.ping_keys) == 19
    assert "ping:217.164.6.212-8333:6549450718434803231" in cache.ping_keys

    assert len(cache.invs[2]) == 2

    key = list(cache.invs[2].keys())[0]
    _, type, hash = key.split(":")
    assert int(type) == 2
    assert hash == "000000000000000001b53761fcbfa1eb3422cae8c53bb5f69f59a6246f6889de"
    assert len(cache.invs[2][key]) == 1

    assert len(cache.invs[1]) == 1089
    assert sum([len(v) for v in cache.invs[1].values()]) == 4488

    key = list(cache.invs[1].keys())[0]
    _, type, bucket, hash = key.split(":")
    assert int(type) == 1
    assert int(bucket) == (int(1759791402902 / 1000) // 3600) % 10
    assert hash == "d5f833258a9f5c8a4ae581801402e1b2a883e65465a69f8b028e2aa54542fb17"
    assert len(cache.invs[1][key]) == 10
    assert cache.invs[1][key] == sorted(cache.invs[1][key])
    assert cache.invs[1][key][0] == 1759791402902
    assert cache.invs[1][key][-1] == 1759791402917

    buckets = [int(key.split(":")[2]) for key in cache.invs[1].keys()]
    assert all(bucket == 0 for bucket in buckets)

    timestamps = cache.invs[1][
        "inv:1:0:d5f833258a9f5c8a4ae581801402e1b2a883e65465a69f8b028e2aa54542fb17"
    ]
    changes = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    assert changes == [1, 1, 1, 2, 3, 6, 1, 0, 0]

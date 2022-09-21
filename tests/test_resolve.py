#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
from unittest import mock

from resolve import Resolve
from resolve import init_conf
from utils import new_redis_conn


@mock.patch('redis.StrictRedis')
def test_resolve_addresses(mock_strict_redis):
    mock_strict_redis.return_value.ttl.return_value = 0

    json_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'data',
        '1663113591.json')
    nodes = json.loads(open(json_filepath, 'r').read())
    addresses = set([node[0] for node in nodes][:20])

    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..',
        'conf',
        'resolve.conf.default')
    init_conf(conf_filepath)

    redis_conn = new_redis_conn(db=0)

    resolve = Resolve(addresses=addresses, redis_conn=redis_conn)
    resolve.resolve_addresses()

    assert sorted(list(resolve.resolved.keys())) == ['geoip', 'hostname']
    assert len(resolve.resolved['geoip']) == 20
    assert len(resolve.resolved['hostname']) == 8
    assert sorted(resolve.resolved['geoip'].keys()) == [
        '111.220.45.48',
        '172.105.19.104',
        '2003:e6:7f0c:f00:dea6:32ff:fe30:76b2',
        '24.137.223.25',
        '3.8.101.76',
        '54.254.244.105',
        '71.11.65.7',
        '89.110.53.4',
        'adznbcp5k7jjok3h6kskksh2ynlucdkkrcif6pupxavh3sdl53nckuid.onion',
        'be4up3gysjhnyr5bxqynk2zdhwe6aoh7u2bkb2ug2m2ctcviz5gnavad.onion',
        'fgv7obhyv2uydyhj2fuxwfkvoapdxtowidp3gwnrjkakhigxjiv4ajyd.onion',
        'jwvkjv4ovzh63gxwgwx45ds2lly2cstwpc3gjqkgnpgne2zke5lykmqd.onion',
        'laffj3nzorq6jmtqovdekbagd4dt23p33zijxvcku7yzd5ibrzlmmwqd.onion',
        'okf7bcj2ynuim6dcpmp3mnzndolcq3p2fgw3deatkzj25iqrczjrfnqd.onion',
        'q3xg3m46kboi3o64wfortrcfrgnazs2qvzkro4a43fesczebrqnf63id.onion',
        'rssxdsblkulp4i7uwawrqpdao5wbns2qnqqbm22ijhzg3tcnuuceclyd.onion',
        'tjjlfpyzsedpeqnuwt5tu42oj3qq3v57ipkb543zzgidib2hloq4oyid.onion',
        'uzchs32yms7izgfn442y7ybauvar6arwnth23wiuyf75mpdb4x27ssyd.onion',
        'vh3hoeihj3ccsychqoaqpq2mjfbxca32yza35tb5ruiqeadv7yapccyd.onion',
        'zqhfuceb3yx3rdxhpn2bui6t2wduqwq6m6kjmlhzfx4iak3vyemf3nid.onion',
    ]
    assert resolve.resolved['geoip']['3.8.101.76'][-1] == 'AMAZON-02'


def test_raw_hostname():
    hostname = Resolve().raw_hostname('1.1.1.1')
    assert hostname == 'one.one.one.one'


def test_raw_geoip():
    geoip = Resolve().raw_geoip('1.1.1.1')
    assert geoip == (
        None,
        None,
        0.0,
        0.0,
        None,
        'AS13335',
        'CLOUDFLARENET',
    )

    geoip = Resolve().raw_geoip('2606:4700:4700::1111')
    assert geoip == (
        None,
        'US',
        37.751,
        -97.822,
        'America/Chicago',
        'AS13335',
        'CLOUDFLARENET',
    )

    geoip = Resolve().raw_geoip(
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion')
    assert geoip == (
        None,
        None,
        0.0,
        0.0,
        None,
        'TOR',
        'Tor network',
    )

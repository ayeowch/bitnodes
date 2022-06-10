#!/usr/bin/env python
# -*- coding: utf-8 -*-
from resolve import Resolve


def test_raw_geoip():
    geoip = Resolve().raw_geoip('1.1.1.1')
    assert geoip == (
        None,
        'AU',
        -33.494,
        143.2104,
        'Australia/Sydney',
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

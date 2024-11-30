#!/usr/bin/env python
# -*- coding: utf-8 -*-
from io import BytesIO

from protocol import NETWORK_I2P, NETWORK_IPV4, NETWORK_IPV6, NETWORK_TORV3, Serializer


def test_deserialize_network_address():
    hex_str = "00f15365fd090c010400000000208d"
    data = BytesIO(bytes.fromhex(hex_str))
    assert Serializer().deserialize_network_address(
        data, has_timestamp=True, version=2
    ) == {
        "network_id": NETWORK_IPV4,
        "timestamp": 1700000000,
        "services": 3081,
        "ipv4": "0.0.0.0",
        "ipv6": "",
        "onion": "",
        "i2p": "",
        "cjdns": "",
        "port": 8333,
    }

    hex_str = "00f15365fd090c021000000000000000000000000000000000208d"
    data = BytesIO(bytes.fromhex(hex_str))
    assert Serializer().deserialize_network_address(
        data, has_timestamp=True, version=2
    ) == {
        "network_id": NETWORK_IPV6,
        "timestamp": 1700000000,
        "services": 3081,
        "ipv4": "",
        "ipv6": "::",
        "onion": "",
        "i2p": "",
        "cjdns": "",
        "port": 8333,
    }

    hex_str = "00f15365fd090c04200000000000000000000000000000000000000000000000000000000000000000208d"
    data = BytesIO(bytes.fromhex(hex_str))
    assert Serializer().deserialize_network_address(
        data, has_timestamp=True, version=2
    ) == {
        "network_id": NETWORK_TORV3,
        "timestamp": 1700000000,
        "services": 3081,
        "ipv4": "",
        "ipv6": "",
        "onion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion",
        "i2p": "",
        "cjdns": "",
        "port": 8333,
    }

    hex_str = "00f15365fd090c0520e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000"
    data = BytesIO(bytes.fromhex(hex_str))
    assert Serializer().deserialize_network_address(
        data, has_timestamp=True, version=2
    ) == {
        "network_id": NETWORK_I2P,
        "timestamp": 1700000000,
        "services": 3081,
        "ipv4": "",
        "ipv6": "",
        "onion": "",
        "i2p": "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.b32.i2p",
        "cjdns": "",
        "port": 0,
    }

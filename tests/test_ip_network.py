#!/usr/bin/env python
# -*- coding: utf-8 -*-
from utils import ip_to_network


def test_ip_to_network():
    assert (
        ip_to_network('2a01:4f8:10a:37ee::2', 64) ==
        '2a01:4f8:10a:37ee::/64')

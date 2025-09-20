#!/usr/bin/env python
# -*- coding: utf-8 -*-
from utils import ip_port_list, txt_items


def test_ip_port_list():
    txt = """
149.56.185.56:9001 # OVH
[2a02:7b40:592f:a187::1]:8333 # UAB
"""
    assert set(ip_port_list(txt_items(txt))) == {
        ("2a02:7b40:592f:a187::1", 8333),
        ("149.56.185.56", 9001),
    }

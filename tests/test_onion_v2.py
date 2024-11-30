#!/usr/bin/env python
# -*- coding: utf-8 -*-
from protocol import addr_to_onion_v2


def test_addr_to_onion_v2():
    addr = bytearray.fromhex("361baa9a82df6a854b41")
    assert addr_to_onion_v2(addr) == "gyn2vguc35viks2b.onion"

#!/usr/bin/env python
# -*- coding: utf-8 -*-
from protocol import addr_to_onion_v3


def test_addr_to_onion_v3():
    addr = bytearray.fromhex(
        '53f75b474bcc984e37efbdc130c19c95d93f4cdbfea50d3eb61118ea65446ef5')

    assert (
        addr_to_onion_v3(addr) ==
        'kp3vwr2lzsme4n7pxxatbqm4sxmt6tg372sq2pvwcemouzken325dkad.onion')

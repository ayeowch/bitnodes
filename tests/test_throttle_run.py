#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time

from utils import throttle_run


@throttle_run(ttl=0.01)
def func():
    return True


def test_throttle_run():
    values = []
    for _ in range(12):
        values.append(func())
        time.sleep(0.001)
    assert values.count(True) == 2

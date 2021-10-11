#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from crawl import CONF, init_conf, update_excluded_networks


def test_update_excluded_networks():
    filepath = os.path.realpath(__file__)
    confpath = os.path.join(
        os.path.dirname(filepath), '..', 'conf', 'crawl.conf.default')
    init_conf([filepath, confpath, 'master'])

    assert len(CONF['default_exclude_ipv4_networks']) == 22
    assert len(CONF['default_exclude_ipv6_networks']) == 0

    update_excluded_networks()

    assert len(CONF['exclude_ipv4_networks']) > 0
    assert len(CONF['exclude_ipv6_networks']) == 0

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest
from unittest.mock import MagicMock
from unittest import mock

from crawl import CONF
from crawl import connect
from crawl import get_cached_peers
from crawl import get_peers
from crawl import getaddr
from crawl import init_conf
from crawl import update_excluded_networks


class CrawlTestCase(unittest.TestCase):
    def setUp(self):
        conf_filepath = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '..',
            'conf',
            'crawl.conf.default')
        init_conf([None, conf_filepath, 'master'])

        CONF['socket_timeout'] = 1

        self.redis_conn = MagicMock()
        self.conn = MagicMock()

    def test_getaddr(self):
        msgs = getaddr(self.conn)
        self.assertEqual(msgs, [])

    def test_get_peers(self):
        peers = get_peers(self.conn)
        self.assertEqual(peers, [])

    def test_get_cached_peers(self):
        self.redis_conn.get.return_value = b'[]'
        peers = get_cached_peers(self.conn, self.redis_conn)
        self.assertEqual(peers, set([]))

    @mock.patch('crawl.Connection')
    def test_connect(self, mock_connection):
        def mock_redis_conn_get(*args, **kwargs):
            if args[0] == 'height':
                return 1
            return b'[]'
        self.redis_conn.get.side_effect = mock_redis_conn_get

        key = 'node:127.0.0.1-8333-1'
        connect(key, self.redis_conn)
        self.assertEqual(
            mock_connection.call_args.kwargs['user_agent'],
            '/bitnodes.io:0.3/')

    def test_update_excluded_networks(self):
        def mock_redis_conn_get(*args, **kwargs):
            return b'set()'
        self.redis_conn.get.side_effect = mock_redis_conn_get

        assert CONF['current_exclude_ipv4_networks'] is None
        assert CONF['current_exclude_ipv4_networks'] is None

        update_excluded_networks(self.redis_conn)

        assert len(CONF['current_exclude_ipv4_networks']) == 0
        assert len(CONF['current_exclude_ipv6_networks']) == 0

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest
from unittest import mock
from unittest.mock import MagicMock

from crawl import (
    CONF,
    connect,
    get_cached_peers,
    get_peers,
    getaddr,
    init_conf,
    set_max_age,
    update_excluded_networks,
    update_excluded_nodes,
)


class CrawlTestCase(unittest.TestCase):
    def setUp(self):
        conf_filepath = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "..",
            "conf",
            "crawl.conf.default",
        )
        init_conf([None, conf_filepath, "master"])

        CONF["socket_timeout"] = 1

        self.redis_conn = MagicMock()
        self.conn = MagicMock()

    def test_getaddr(self):
        msgs = getaddr(self.conn)
        self.assertEqual(msgs, [])

    def test_get_peers(self):
        peers = get_peers(self.conn)
        self.assertEqual(peers, [])

    def test_get_cached_peers(self):
        self.redis_conn.get.return_value = b"[]"
        peers = get_cached_peers(self.conn, self.redis_conn)
        self.assertEqual(peers, set([]))

    @mock.patch("crawl.Connection")
    def test_connect(self, mock_connection):
        def mock_redis_conn_get(*args, **kwargs):
            if args[0] == "height":
                return 1
            return b"[]"

        self.redis_conn.get.side_effect = mock_redis_conn_get

        mock_connection.return_value.handshake.return_value = {"version": 70016}

        key = "node:127.0.0.1-8333-1"
        connect(key, self.redis_conn)
        self.assertEqual(
            mock_connection.call_args.kwargs["user_agent"], "/bitnodes.io:0.3/"
        )

    def test_set_max_age(self):
        def mock_redis_conn_lrange(*args, **kwargs):
            if args[0] == "elapsed":
                return [
                    "[1700000003, 900]",
                    "[1700000002, 800]",
                    "[1700000001, 700]",
                    "[1700000000, 600]",
                ]
            return []

        self.redis_conn.lrange.side_effect = mock_redis_conn_lrange

        assert CONF["snapshot_delay"] == 600
        assert CONF["current_max_age"] == 432_000

        set_max_age(self.redis_conn)

        assert CONF["current_max_age"] == 345_600

    @mock.patch("crawl.http_get_txt")
    def test_update_excluded_networks(self, mock_http_get_txt):
        def mock_redis_conn_get(*args, **kwargs):
            if args[0] == "exclude-ipv4-networks":
                return b"[[1, 2], [3, 4]]"
            elif args[0] == "exclude-ipv6-networks":
                return b"[[5, 6], [7, 8]]"
            return b"[]"

        self.redis_conn.get.side_effect = mock_redis_conn_get

        assert CONF["current_exclude_ipv4_networks"] == set()
        assert CONF["current_exclude_ipv4_networks"] == set()

        update_excluded_networks(self.redis_conn)

        assert CONF["current_exclude_ipv4_networks"] == {(1, 2), (3, 4)}
        assert CONF["current_exclude_ipv6_networks"] == {(5, 6), (7, 8)}

    @mock.patch("crawl.http_get_txt")
    def test_update_excluded_nodes(self, mock_http_get_txt):
        def mock_redis_conn_get(*args, **kwargs):
            return b'["127.0.0.1", "127.0.0.2"]'

        self.redis_conn.get.side_effect = mock_redis_conn_get

        assert CONF["current_exclude_nodes"] == set()

        update_excluded_nodes(self.redis_conn)

        assert CONF["current_exclude_nodes"] == {"127.0.0.1", "127.0.0.2"}

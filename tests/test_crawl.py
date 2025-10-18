#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest
from ipaddress import ip_address, ip_network
from unittest import mock
from unittest.mock import MagicMock

from crawl import (
    CONF,
    connect,
    get_cached_peers,
    get_peers,
    getaddr,
    init_conf,
    list_excluded_networks,
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

    @property
    def conn(self):
        return MagicMock()

    def test_getaddr(self):
        msgs = getaddr(self.conn)
        self.assertEqual(msgs, [])

    def test_get_peers(self):
        peers = get_peers(self.conn)
        self.assertEqual(peers, [])

    @mock.patch("crawl.get_peers")
    def test_get_cached_peers(self, mock_get_peers):
        self.redis_conn.get.return_value = b"[]"
        peers = get_cached_peers(self.conn, self.redis_conn)
        self.assertEqual(peers, set([]))

        mock_get_peers.return_value = [("0.0.0.0", 0, 0, 0)]
        self.redis_conn.get.return_value = None
        for _ in range(40):
            get_cached_peers(self.conn, self.redis_conn)
        a, b = CONF["addr_ttl"]
        mode = (a + b) / 2
        ms = [kwargs["px"] for _, kwargs in self.redis_conn.set.call_args_list]
        avg_ms = sum(ms) / len(ms)
        assert int(avg_ms / 1000 / 3600) == int(mode / 3600)

    def test_onion_get_cached_peers(self):
        CONF["onion_peers_sampling_rate"] = 0

        self.conn.to_addr = (
            "3ooytgoomej62ddt4nz2lrbcptmdq7i5sbyltxicjetobuol2jz6lbqd.onion",
            8333,
        )

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

        assert CONF["current_max_age"] == 276_480

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

    def test_list_excluded_networks(self):
        networks = {"194.85.0.0/18", "194.85.23.0/24"}
        collapsed_networks = []
        for net in list_excluded_networks(networks):
            collapsed_networks.append(
                str(ip_network(f"{ip_address(net[0])}/{bin(net[1]).count('1')}"))
            )
        assert collapsed_networks == ["194.85.0.0/18"]

        networks = {"2a01:7e00::/29", "2a01:7e00::/40"}
        collapsed_networks = []
        for net in list_excluded_networks(networks):
            collapsed_networks.append(
                str(ip_network(f"{ip_address(net[0])}/{bin(net[1]).count('1')}"))
            )
        assert collapsed_networks == ["2a01:7e00::/29"]

    @mock.patch("crawl.http_get_txt")
    def test_update_excluded_nodes(self, mock_http_get_txt):
        def mock_redis_conn_get(*args, **kwargs):
            return b'["127.0.0.1", "127.0.0.2"]'

        self.redis_conn.get.side_effect = mock_redis_conn_get

        assert CONF["current_exclude_nodes"] == set()

        update_excluded_nodes(self.redis_conn)

        assert CONF["current_exclude_nodes"] == {"127.0.0.1", "127.0.0.2"}

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import socket
import unittest
from unittest import mock
from unittest.mock import MagicMock

from ping import ConnectionManager, init_conf


class PingTestCase(unittest.TestCase):
    def setUp(self):
        conf_filepath = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "..",
            "conf",
            "ping.conf.default",
        )
        init_conf([None, conf_filepath, "master"])

        self.redis_conn = MagicMock()

    @mock.patch("ping.time.time", return_value=1700000000)
    @mock.patch("ping.Connection")
    def test_connect(self, mock_connection, mock_time):
        self.redis_conn.spop.return_value = b'["127.0.0.1", 8333, 1, 1]'
        self.redis_conn.zadd.return_value = 1

        mock_connection.return_value.to_addr = ("127.0.0.1", 8333)
        mock_connection.return_value.handshake.return_value = {"version": 70016}

        mock_connection.return_value.get_messages.side_effect = socket.error

        ConnectionManager(redis_conn=self.redis_conn).connect()

        self.assertEqual(
            self.redis_conn.method_calls,
            [
                mock.call.spop("reachable"),
                mock.call.zadd("open", {'["127.0.0.1", 8333]': 1700000000}, nx=True),
                mock.call.pipeline(),
                mock.call.zadd(
                    "opendata",
                    {'["127.0.0.1", 8333, 70016, "", 1700000000, ""]': 1700000000},
                ),
                mock.call.zrem(
                    "opendata", '["127.0.0.1", 8333, 70016, "", 1700000000, ""]'
                ),
                mock.call.zrem("open", '["127.0.0.1", 8333]'),
            ],
        )

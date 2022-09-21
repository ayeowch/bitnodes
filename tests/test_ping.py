#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import socket
import unittest
from unittest.mock import MagicMock
from unittest import mock

from ping import init_conf
from ping import task


class PingTestCase(unittest.TestCase):
    def setUp(self):
        conf_filepath = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '..',
            'conf',
            'ping.conf.default')
        init_conf([None, conf_filepath, 'master'])

        self.redis_conn = MagicMock()

    @mock.patch('ping.Connection')
    def test_task(self, mock_connection):
        self.redis_conn.spop.return_value = b"('127.0.0.1', 8333, 1, 1)"
        self.redis_conn.sadd.return_value = 1

        mock_connection.return_value.get_messages.side_effect = socket.error

        task(self.redis_conn)

        self.assertEqual(
            self.redis_conn.method_calls[-1],
            mock.call.srem('open', "('127.0.0.1', 8333)"))

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from unittest import mock

from binascii import unhexlify

from pcap import Cache


@mock.patch.object(Cache, "cache_message")
def test_cache_messages(mock_cache_message):
    filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "inv.pcap"
    )

    cache = Cache(filepath, magic_number=unhexlify("f9beb4d9"))

    with mock.patch.object(
        cache.serializer,
        "deserialize_msg",
        wraps=cache.serializer.deserialize_msg,
    ) as mock_deserialize_msg:
        cache.cache_messages()

        assert mock_cache_message.call_count == 2
        assert mock_deserialize_msg.call_count == 2

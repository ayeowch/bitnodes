#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# protocol.py - Bitcoin protocol access for Bitnodes.
#
# Copyright (c) Addy Yeow <ayeowch@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Bitcoin protocol access for Bitnodes.
Reference: https://en.bitcoin.it/wiki/Protocol_specification

-------------------------------------------------------------------------------
                     PACKET STRUCTURE FOR BITCOIN PROTOCOL
                           protocol version >= 70001
-------------------------------------------------------------------------------
[---MESSAGE---]
[ 4] MAGIC_NUMBER               (\xF9\xBE\xB4\xD9)                  uint32_t
[12] COMMAND                                                        char[12]
[ 4] LENGTH                     <I (len(payload))                   uint32_t
[ 4] CHECKSUM                   (sha256(sha256(payload))[:4])       uint32_t
[..] PAYLOAD                    see below

    [---VERSION_PAYLOAD---]
    [ 4] VERSION                <i                                  int32_t
    [ 8] SERVICES               <Q                                  uint64_t
    [ 8] TIMESTAMP              <q                                  int64_t
    [..] ADDR_RECV
        [ADDR_PAYLOAD|ADDRV2_PAYLOAD] (without TIMESTAMP)
    [..] ADDR_FROM
        [ADDR_PAYLOAD|ADDRV2_PAYLOAD] (without TIMESTAMP)
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t
    [..] USER_AGENT             variable string
    [ 4] HEIGHT                 <i                                  int32_t
    [ 1] RELAY                  <? (since version >= 70001)         bool

    [---ADDR_LIST_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] ADDR_LIST              multiple of COUNT (max 1000)
        [ADDR_PAYLOAD|ADDRV2_PAYLOAD]

    [---ADDR_PAYLOAD---]
    [ 4] TIMESTAMP              <I                                  uint32_t
    [ 8] SERVICES               <Q                                  uint64_t
    [16] IP_ADDR
        [12] IPV6               (\x00 * 10 + \xFF * 2)              char[12]
        [ 4] IPV4                                                   char[4]
    [ 2] PORT                   >H                                  uint16_t

    [---ADDRV2_PAYLOAD---]
    [ 4] TIMESTAMP              <I                                  uint32_t
    [..] SERVICES               variable integer
    [ 1] NETWORK_ID             <B                                  uint8_t
    [..] ADDR                   variable integer up to 512 bytes
    [ 2] PORT                   >H                                  uint16_t

    [---PING_PAYLOAD---]
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t

    [---PONG_PAYLOAD---]
    [ 8] NONCE                  <Q (nonce from ping)                uint64_t

    [---INV_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] INVENTORY              multiple of COUNT (max 50000)
        [ 4] TYPE               <I (0=error, 1=tx, 2=block)         uint32_t
        [32] HASH                                                   char[32]

    [---TX_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] TX_IN_COUNT            variable integer
    [..] TX_IN                  multiple of TX_IN_COUNT
        [32] PREV_OUT_HASH                                          char[32]
        [ 4] PREV_OUT_INDEX     <I (zero-based)                     uint32_t
        [..] SCRIPT_LENGTH      variable integer
        [..] SCRIPT             variable string
        [ 4] SEQUENCE           <I                                  uint32_t
    [..] TX_OUT_COUNT           variable integer
    [..] TX_OUT                 multiple of TX_OUT_COUNT
        [ 8] VALUE              <q                                  int64_t
        [..] SCRIPT_LENGTH      variable integer
        [..] SCRIPT             variable string
    [ 4] LOCK_TIME              <I                                  uint32_t

    [---BLOCK_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [32] PREV_BLOCK_HASH                                            char[32]
    [32] MERKLE_ROOT                                                char[32]
    [ 4] TIMESTAMP              <I                                  uint32_t
    [ 4] BITS                   <I                                  uint32_t
    [ 4] NONCE                  <I                                  uint32_t
    [..] TX_COUNT               variable integer
    [..] TX                     multiple of TX_COUNT
        [..] TX                 see TX_PAYLOAD

    [---GETBLOCKS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---GETHEADERS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---HEADERS_PAYLOAD---]
    [..] COUNT                  variable integer (max 2000)
    [..] HEADERS                multiple of COUNT
        [ 4] VERSION            <I                                  uint32_t
        [32] PREV_BLOCK_HASH                                        char[32]
        [32] MERKLE_ROOT                                            char[32]
        [ 4] TIMESTAMP          <I                                  uint32_t
        [ 4] BITS               <I                                  uint32_t
        [ 4] NONCE              <I                                  uint32_t
        [..] TX_COUNT           variable integer (always 0)
-------------------------------------------------------------------------------
"""

import hashlib
import logging
import random
import socket
import struct
import sys
import time
from base64 import b32decode, b32encode
from collections import deque
from io import BytesIO, SEEK_CUR

import gevent
import socks
from binascii import hexlify, unhexlify

MAGIC_NUMBER = b"\xF9\xBE\xB4\xD9"
PORT = 8333
MIN_PROTOCOL_VERSION = 70001
PROTOCOL_VERSION = 70016
FROM_SERVICES = 0
TO_SERVICES = 1  # NODE_NETWORK
USER_AGENT = "/bitnodes.io:0.3/"
HEIGHT = 754565
RELAY = 0  # Set to 1 to receive all txs.

SOCKET_BUFSIZE = 8192
SOCKET_TIMEOUT = 30
HEADER_LEN = 24

# IPv6 prefix for .onion address (use in addr message only).
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"

# Reserved network IDs.
NETWORK_IPV4 = 1
NETWORK_IPV6 = 2
NETWORK_TORV2 = 3
NETWORK_TORV3 = 4
NETWORK_I2P = 5
NETWORK_CJDNS = 6

NETWORK_LENGTHS = {
    NETWORK_IPV4: 4,
    NETWORK_IPV6: 16,
    NETWORK_TORV2: 10,
    NETWORK_TORV3: 32,
    NETWORK_I2P: 32,
    NETWORK_CJDNS: 16,
}

SUPPORTED_NETWORKS = [
    NETWORK_IPV4,
    NETWORK_IPV6,
    NETWORK_TORV2,
    NETWORK_TORV3,
]

ONION_V3_LEN = 62


class ProtocolError(Exception):
    pass


class ConnectionError(Exception):
    pass


class HeaderTooShortError(ProtocolError):
    pass


class InvalidMagicNumberError(ProtocolError):
    pass


class PayloadTooShortError(ProtocolError):
    pass


class InvalidPayloadChecksum(ProtocolError):
    pass


class IncompatibleClientError(ProtocolError):
    pass


class UnknownNetworkIdError(ProtocolError):
    pass


class UnsupportedNetworkIdError(ProtocolError):
    pass


class InvalidAddrLenError(ProtocolError):
    pass


class ReadError(ProtocolError):
    pass


class ProxyRequired(ConnectionError):
    pass


class RemoteHostClosedConnection(ConnectionError):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def addr_to_onion_v2(addr):
    """
    Returns .onion address for the specified v2 onion addr.
    """
    return (b32encode(addr).lower() + b".onion").decode()


def addr_to_onion_v3(addr):
    """
    Returns .onion address for the specified v3 onion addr (PUBKEY).

    onion_address = base32(PUBKEY | CHECKSUM | VERSION) + '.onion'
    See https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
    """
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + addr + version).digest()[:2]
    return (b32encode(addr + checksum + version).lower() + b".onion").decode()


def unpack(fmt, string):
    """
    Wraps problematic struct.unpack() in a try statement.
    """
    try:
        return struct.unpack(fmt, string)[0]
    except struct.error as err:
        raise ReadError(err)


def create_connection(address, timeout=SOCKET_TIMEOUT, source_address=None, proxy=None):
    if address[0].endswith(".onion") and proxy is None:
        raise ProxyRequired("tor proxy is required to connect to .onion address")
    if proxy:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy[0], proxy[1])
        sock = socks.socksocket()
        sock.settimeout(timeout)
        try:
            sock.connect(address)
        except socks.ProxyError as err:
            raise ConnectionError(err)
        return sock
    if ":" in address[0] and source_address and ":" not in source_address[0]:
        source_address = None
    return socket.create_connection(
        address, timeout=timeout, source_address=source_address
    )


class Serializer(object):
    def __init__(self, **conf):
        self.magic_number = conf.get("magic_number", MAGIC_NUMBER)
        if isinstance(self.magic_number, str):
            self.magic_number = unhexlify(self.magic_number)
        self.protocol_version = conf.get("protocol_version", PROTOCOL_VERSION)
        self.to_services = conf.get("to_services", TO_SERVICES)
        self.from_services = conf.get("from_services", FROM_SERVICES)
        self.user_agent = conf.get("user_agent", USER_AGENT)
        self.height = conf.get("height", HEIGHT)
        if self.height is None:
            self.height = HEIGHT
        self.relay = conf.get("relay", RELAY)

        # This is set prior to throwing PayloadTooShortError exception to
        # allow caller to fetch more data over the network.
        self.required_len = 0

        # Bump to 2 during handshake on receipt of sendaddrv2 message.
        self.addr_version = None

    def serialize_msg(self, **kwargs):
        command = kwargs["command"]
        msg = [
            self.magic_number,
            command + b"\x00" * (12 - len(command)),
        ]

        payload = b""
        if command == b"version":
            to_addr = (self.to_services,) + kwargs["to_addr"]
            from_addr = (self.from_services,) + kwargs["from_addr"]
            payload = self.serialize_version_payload(to_addr, from_addr)
        elif command == b"ping" or command == b"pong":
            nonce = kwargs["nonce"]
            payload = self.serialize_ping_payload(nonce)
        elif command == b"addr":
            addr_list = kwargs["addr_list"]
            payload = self.serialize_addr_payload(addr_list)
        elif command == b"inv" or command == b"getdata":
            inventory = kwargs["inventory"]
            payload = self.serialize_inv_payload(inventory)
        elif command == b"getblocks" or command == b"getheaders":
            block_hashes = kwargs["block_hashes"]
            last_block_hash = kwargs["last_block_hash"]
            payload = self.serialize_getblocks_payload(block_hashes, last_block_hash)
        elif command == b"headers":
            headers = kwargs["headers"]
            payload = self.serialize_block_headers_payload(headers)

        msg.extend(
            [
                struct.pack("<I", len(payload)),
                sha256(sha256(payload))[:4],
                payload,
            ]
        )

        return b"".join(msg)

    def deserialize_msg(self, data):
        msg = {}

        data_len = len(data)
        if data_len < HEADER_LEN:
            raise HeaderTooShortError(f"got {data_len} of {HEADER_LEN} bytes")

        data = BytesIO(data)
        header = data.read(HEADER_LEN)
        msg.update(self.deserialize_header(header))

        if (data_len - HEADER_LEN) < msg["length"]:
            self.required_len = HEADER_LEN + msg["length"]
            raise PayloadTooShortError(f"got {data_len} of {self.required_len} bytes")

        payload = data.read(msg["length"])
        computed_checksum = sha256(sha256(payload))[:4]
        if computed_checksum != msg["checksum"]:
            raise InvalidPayloadChecksum(
                f"{hexlify(computed_checksum)} != {hexlify(msg['checksum'])}"
            )

        if msg["command"] == b"version":
            msg.update(self.deserialize_version_payload(payload))
        elif msg["command"] == b"ping" or msg["command"] == b"pong":
            msg.update(self.deserialize_ping_payload(payload))
        elif msg["command"] == b"addr":
            msg.update(self.deserialize_addr_payload(payload))
        elif msg["command"] == b"addrv2":
            msg.update(self.deserialize_addr_payload(payload, version=2))
        elif msg["command"] == b"inv":
            msg.update(self.deserialize_inv_payload(payload))
        elif msg["command"] == b"tx":
            msg.update(self.deserialize_tx_payload(payload))
        elif msg["command"] == b"block":
            msg.update(self.deserialize_block_payload(payload))
        elif msg["command"] == b"headers":
            msg.update(self.deserialize_block_headers_payload(payload))

        return (msg, data.read())

    def deserialize_header(self, data):
        msg = {}
        data = BytesIO(data)

        msg["magic_number"] = data.read(4)
        if msg["magic_number"] != self.magic_number:
            raise InvalidMagicNumberError(
                f"{hexlify(msg['magic_number'])} " f"!= {hexlify(self.magic_number)}"
            )

        msg["command"] = data.read(12).strip(b"\x00")
        msg["length"] = struct.unpack("<I", data.read(4))[0]
        msg["checksum"] = data.read(4)

        return msg

    def serialize_version_payload(self, to_addr, from_addr):
        payload = [
            struct.pack("<i", self.protocol_version),
            struct.pack("<Q", self.from_services),
            struct.pack("<q", int(time.time())),
            self.serialize_network_address(to_addr, version=self.addr_version),
            self.serialize_network_address(from_addr, version=self.addr_version),
            struct.pack("<Q", random.getrandbits(64)),
            self.serialize_string(self.user_agent),
            struct.pack("<i", self.height),
            struct.pack("<?", self.relay),
        ]
        return b"".join(payload)

    def deserialize_version_payload(self, data):
        msg = {}
        data = BytesIO(data)

        msg["version"] = unpack("<i", data.read(4))
        if msg["version"] < MIN_PROTOCOL_VERSION:
            raise IncompatibleClientError(f"{msg['version']} < {MIN_PROTOCOL_VERSION}")

        msg["services"] = unpack("<Q", data.read(8))
        msg["timestamp"] = unpack("<q", data.read(8))

        msg["to_addr"] = self.deserialize_network_address(
            data, version=self.addr_version
        )
        msg["from_addr"] = self.deserialize_network_address(
            data, version=self.addr_version
        )

        msg["nonce"] = unpack("<Q", data.read(8))

        msg["user_agent"] = self.deserialize_string(data)[1].decode()

        msg["height"] = unpack("<i", data.read(4))

        try:
            msg["relay"] = struct.unpack("<?", data.read(1))[0]
        except struct.error:
            msg["relay"] = False

        return msg

    def serialize_ping_payload(self, nonce):
        payload = [
            struct.pack("<Q", nonce),
        ]
        return b"".join(payload)

    def deserialize_ping_payload(self, data):
        data = BytesIO(data)
        nonce = unpack("<Q", data.read(8))
        msg = {
            "nonce": nonce,
        }
        return msg

    def serialize_addr_payload(self, addr_list):
        payload = [
            self.serialize_int(len(addr_list)),
        ]
        payload.extend([self.serialize_network_address(addr) for addr in addr_list])
        return b"".join(payload)

    def deserialize_addr_payload(self, data, version=None):
        msg = {}
        data = BytesIO(data)

        msg["count"] = self.deserialize_int(data)
        msg["addr_list"] = []
        for _ in range(msg["count"]):
            network_address = self.deserialize_network_address(
                data, has_timestamp=True, version=version
            )
            msg["addr_list"].append(network_address)

        return msg

    def serialize_inv_payload(self, inventory):
        payload = [
            self.serialize_int(len(inventory)),
        ]
        payload.extend([self.serialize_inventory(item) for item in inventory])
        return b"".join(payload)

    def deserialize_inv_payload(self, data):
        msg = {
            "timestamp": int(time.time() * 1000),  # milliseconds
        }
        data = BytesIO(data)

        msg["count"] = self.deserialize_int(data)
        msg["inventory"] = []
        for _ in range(msg["count"]):
            inventory = self.deserialize_inventory(data)
            msg["inventory"].append(inventory)

        return msg

    def serialize_tx_payload(self, tx):
        payload = [
            struct.pack("<I", tx["version"]),
            self.serialize_int(tx["tx_in_count"]),
            b"".join([self.serialize_tx_in(tx_in) for tx_in in tx["tx_in"]]),
            self.serialize_int(tx["tx_out_count"]),
            b"".join([self.serialize_tx_out(tx_out) for tx_out in tx["tx_out"]]),
            struct.pack("<I", tx["lock_time"]),
        ]
        return b"".join(payload)

    def deserialize_tx_payload(self, data):
        msg = {}
        if not isinstance(data, BytesIO):
            data = BytesIO(data)

        msg["version"] = unpack("<I", data.read(4))

        # Check for BIP144 marker.
        marker = data.read(1)
        if marker == b"\x00":  # BIP144 marker is set.
            flags = data.read(1)
        else:
            flags = b"\x00"
            data.seek(-1, SEEK_CUR)

        msg["tx_in_count"] = self.deserialize_int(data)
        msg["tx_in"] = []
        for _ in range(msg["tx_in_count"]):
            tx_in = self.deserialize_tx_in(data)
            msg["tx_in"].append(tx_in)

        msg["tx_out_count"] = self.deserialize_int(data)
        msg["tx_out"] = []
        for _ in range(msg["tx_out_count"]):
            tx_out = self.deserialize_tx_out(data)
            msg["tx_out"].append(tx_out)

        if flags != b"\x00":
            for in_num in range(msg["tx_in_count"]):
                msg["tx_in"][in_num].update(
                    {
                        "wits": self.deserialize_string_vector(data),
                    }
                )

        msg["lock_time"] = unpack("<I", data.read(4))

        # Calculate hash from the entire payload.
        payload = self.serialize_tx_payload(msg)
        msg["tx_hash"] = hexlify(sha256(sha256(payload))[::-1])

        return msg

    def deserialize_block_payload(self, data):
        msg = {}

        # Calculate hash from: version (4 bytes) + prev_block_hash (32 bytes) +
        # merkle_root (32 bytes) + timestamp (4 bytes) + bits (4 bytes) +
        # nonce (4 bytes) = 80 bytes
        msg["block_hash"] = hexlify(sha256(sha256(data[:80]))[::-1])

        data = BytesIO(data)

        msg["version"] = struct.unpack("<I", data.read(4))[0]

        # BE (big-endian) -> LE (little-endian)
        msg["prev_block_hash"] = hexlify(data.read(32)[::-1])

        # BE -> LE
        msg["merkle_root"] = hexlify(data.read(32)[::-1])

        msg["timestamp"] = struct.unpack("<I", data.read(4))[0]
        msg["bits"] = struct.unpack("<I", data.read(4))[0]
        msg["nonce"] = struct.unpack("<I", data.read(4))[0]

        msg["tx_count"] = self.deserialize_int(data)
        msg["tx"] = []
        for _ in range(msg["tx_count"]):
            tx_payload = self.deserialize_tx_payload(data)
            msg["tx"].append(tx_payload)

        return msg

    def serialize_getblocks_payload(self, block_hashes, last_block_hash):
        payload = [
            struct.pack("<i", self.protocol_version),
            self.serialize_int(len(block_hashes)),
            b"".join([unhexlify(block_hash)[::-1] for block_hash in block_hashes]),
            unhexlify(last_block_hash)[::-1],  # LE -> BE
        ]
        return b"".join(payload)

    def serialize_block_headers_payload(self, headers):
        payload = [
            self.serialize_int(len(headers)),
        ]
        payload.extend([self.serialize_block_header(header) for header in headers])
        return b"".join(payload)

    def deserialize_block_headers_payload(self, data):
        msg = {}
        data = BytesIO(data)

        msg["count"] = self.deserialize_int(data)
        msg["headers"] = []
        for _ in range(msg["count"]):
            header = self.deserialize_block_header(data)
            msg["headers"].append(header)

        return msg

    def serialize_network_address(self, addr, version=None):
        network_address = []

        if len(addr) == 4:
            (timestamp, services, ip_address, port) = addr
            network_address.append(struct.pack("<I", timestamp))
        else:
            (services, ip_address, port) = addr

        if ip_address.endswith(".onion"):
            if len(ip_address) == ONION_V3_LEN:
                network_id = NETWORK_TORV3
            else:
                network_id = NETWORK_TORV2
        elif "." in ip_address:
            network_id = NETWORK_IPV4
        else:
            network_id = NETWORK_IPV6

        if version == 2:
            network_address.append(self.serialize_int(services))

            if network_id == NETWORK_TORV3:
                # 32 bytes
                network_address.append(b32decode(ip_address[:-6], True)[:32])
            elif network_id == NETWORK_TORV2:
                # 10 bytes
                network_address.append(b32decode(ip_address[:-6], True))
            elif network_id == NETWORK_IPV4:
                # 4 bytes
                network_address.append(socket.inet_pton(socket.AF_INET, ip_address))
            else:
                # 16 bytes
                network_address.append(socket.inet_pton(socket.AF_INET6, ip_address))
        else:
            network_address.append(struct.pack("<Q", services))

            if network_id == NETWORK_TORV2 or network_id == NETWORK_TORV3:
                # Convert .onion address to its IPv6 equivalent (6 + 10 bytes).
                network_address.append(ONION_PREFIX + b32decode(ip_address[:-6], True))
            elif network_id == NETWORK_IPV4:
                # Unused (12 bytes) + IPv4 (4 bytes) = IPv4-mapped IPv6 address
                unused = b"\x00" * 10 + b"\xFF" * 2
                network_address.append(
                    unused + socket.inet_pton(socket.AF_INET, ip_address)
                )
            else:
                # IPv6 (16 bytes)
                network_address.append(socket.inet_pton(socket.AF_INET6, ip_address))

        network_address.append(struct.pack(">H", port))

        return b"".join(network_address)

    def deserialize_network_address(self, data, has_timestamp=False, version=None):
        network_id = 0
        ipv4 = ""
        ipv6 = ""
        onion = ""

        timestamp = None
        if has_timestamp:
            timestamp = unpack("<I", data.read(4))

        if version == 2:
            services = self.deserialize_int(data)

            network_id = unpack("<B", data.read(1))

            if network_id not in NETWORK_LENGTHS.keys():
                raise UnknownNetworkIdError(f"unknown network id {network_id}")

            if network_id not in SUPPORTED_NETWORKS:
                raise UnsupportedNetworkIdError(f"unsupported network id {network_id}")

            addr_len = self.deserialize_int(data)
            if addr_len != NETWORK_LENGTHS[network_id]:
                raise InvalidAddrLenError

            addr = data.read(addr_len)
            if network_id == NETWORK_TORV2:
                onion = addr_to_onion_v2(addr)
            elif network_id == NETWORK_TORV3:
                onion = addr_to_onion_v3(addr)
            elif network_id == NETWORK_IPV6:
                ipv6 = socket.inet_ntop(socket.AF_INET6, addr)
            elif network_id == NETWORK_IPV4:
                ipv4 = socket.inet_ntop(socket.AF_INET, addr)

            port = unpack(">H", data.read(2))
        else:
            services = unpack("<Q", data.read(8))

            _ipv6 = data.read(12)
            _ipv4 = data.read(4)

            port = unpack(">H", data.read(2))

            _ipv6 += _ipv4
            if _ipv6[:6] == ONION_PREFIX:
                onion = addr_to_onion_v2(_ipv6[6:])  # Use .onion
                network_id = NETWORK_TORV2
            else:
                ipv6 = socket.inet_ntop(socket.AF_INET6, _ipv6)
                ipv4 = socket.inet_ntop(socket.AF_INET, _ipv4)
                if ipv4 in ipv6:
                    ipv6 = ""  # Use IPv4
                    network_id = NETWORK_IPV4
                else:
                    ipv4 = ""  # Use IPv6
                    network_id = NETWORK_IPV6

        return {
            "network_id": network_id,
            "timestamp": timestamp,
            "services": services,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "onion": onion,
            "port": port,
        }

    def serialize_inventory(self, item):
        (inv_type, inv_hash) = item
        payload = [
            struct.pack("<I", inv_type),
            unhexlify(inv_hash)[::-1],  # LE -> BE
        ]
        return b"".join(payload)

    def deserialize_inventory(self, data):
        inv_type = unpack("<I", data.read(4))
        inv_hash = data.read(32)[::-1]  # BE -> LE
        return {
            "type": inv_type,
            "hash": hexlify(inv_hash),
        }

    def serialize_tx_in(self, tx_in):
        payload = [
            unhexlify(tx_in["prev_out_hash"])[::-1],  # LE -> BE
            struct.pack("<I", tx_in["prev_out_index"]),
            self.serialize_int(tx_in["script_length"]),
            tx_in["script"],
            struct.pack("<I", tx_in["sequence"]),
        ]
        return b"".join(payload)

    def deserialize_tx_in(self, data):
        prev_out_hash = data.read(32)[::-1]  # BE -> LE
        prev_out_index = unpack("<I", data.read(4))
        script_length, script = self.deserialize_string(data)
        sequence = unpack("<I", data.read(4))
        return {
            "prev_out_hash": hexlify(prev_out_hash),
            "prev_out_index": prev_out_index,
            "script_length": script_length,
            "script": script,
            "sequence": sequence,
        }

    def serialize_tx_out(self, tx_out):
        payload = [
            struct.pack("<q", tx_out["value"]),
            self.serialize_int(tx_out["script_length"]),
            tx_out["script"],
        ]
        return b"".join(payload)

    def deserialize_tx_out(self, data):
        value = unpack("<q", data.read(8))
        script_length = self.deserialize_int(data)
        script = data.read(script_length)
        return {
            "value": value,
            "script_length": script_length,
            "script": script,
        }

    def serialize_block_header(self, header):
        payload = [
            struct.pack("<I", header["version"]),
            unhexlify(header["prev_block_hash"])[::-1],  # LE -> BE
            unhexlify(header["merkle_root"])[::-1],  # LE -> BE
            struct.pack("<I", header["timestamp"]),
            struct.pack("<I", header["bits"]),
            struct.pack("<I", header["nonce"]),
            self.serialize_int(0),
        ]
        return b"".join(payload)

    def deserialize_block_header(self, data):
        header = data.read(80)
        block_hash = sha256(sha256(header))[::-1]  # BE -> LE
        header = BytesIO(header)
        version = struct.unpack("<i", header.read(4))[0]
        prev_block_hash = header.read(32)[::-1]  # BE -> LE
        merkle_root = header.read(32)[::-1]  # BE -> LE
        timestamp = unpack("<I", header.read(4))
        bits = unpack("<I", header.read(4))
        nonce = unpack("<I", header.read(4))
        tx_count = self.deserialize_int(data)
        return {
            "block_hash": hexlify(block_hash),
            "version": version,
            "prev_block_hash": hexlify(prev_block_hash),
            "merkle_root": hexlify(merkle_root),
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce,
            "tx_count": tx_count,
        }

    def serialize_string_vector(self, data):
        payload = [
            self.serialize_int(len(data)),
        ] + [self.serialize_string(item) for item in data]
        return b"".join(payload)

    def deserialize_string_vector(self, data):
        items = []
        count = self.deserialize_int(data)
        for _ in range(count):
            items.append(self.deserialize_string(data)[1])
        return items

    def serialize_string(self, data):
        return self.serialize_int(len(data)) + data.encode()

    def deserialize_string(self, data):
        length = self.deserialize_int(data)
        try:
            str = data.read(length)
        except OverflowError as err:
            raise ReadError(err)
        return (length, str)

    def serialize_int(self, length):
        if length < 0xFD:
            return chr(length).encode()
        elif length <= 0xFFFF:
            return chr(0xFD).encode() + struct.pack("<H", length)
        elif length <= 0xFFFFFFFF:
            return chr(0xFE).encode() + struct.pack("<I", length)
        return chr(0xFF).encode() + struct.pack("<Q", length)

    def deserialize_int(self, data):
        length = unpack("<B", data.read(1))
        if length == 0xFD:
            length = unpack("<H", data.read(2))
        elif length == 0xFE:
            length = unpack("<I", data.read(4))
        elif length == 0xFF:
            length = unpack("<Q", data.read(8))
        return length


class Connection(object):
    def __init__(self, to_addr, from_addr=("0.0.0.0", 0), **conf):
        self.to_addr = to_addr
        self.from_addr = from_addr
        self.serializer = Serializer(**conf)
        self.socket_timeout = conf.get("socket_timeout", SOCKET_TIMEOUT)
        self.proxy = conf.get("proxy", None)
        self.socket = None
        # Bits per second (bps) samples for this connection.
        self.bps = deque([], maxlen=128)

    def open(self):
        self.socket = create_connection(
            self.to_addr,
            timeout=self.socket_timeout,
            source_address=self.from_addr,
            proxy=self.proxy,
        )

    def close(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            finally:
                self.socket.close()

    def send(self, data):
        self.socket.sendall(data)

    def recv(self, length=0):
        start_t = time.time()
        if length > 0:
            chunks = []
            while length > 0:
                chunk = self.socket.recv(SOCKET_BUFSIZE)
                if not chunk:
                    raise RemoteHostClosedConnection(
                        f"{self.to_addr} closed connection"
                    )
                chunks.append(chunk)
                length -= len(chunk)
            data = b"".join(chunks)
        else:
            data = self.socket.recv(SOCKET_BUFSIZE)
            if not data:
                raise RemoteHostClosedConnection(f"{self.to_addr} closed connection")
        if len(data) > SOCKET_BUFSIZE:
            end_t = time.time()
            self.bps.append((len(data) * 8) / (end_t - start_t))
        return data

    def get_messages(self, length=0, commands=None):
        msgs = []
        data = self.recv(length=length)
        while len(data) > 0:
            gevent.sleep(0)
            try:
                (msg, data) = self.serializer.deserialize_msg(data)
            except PayloadTooShortError:
                data += self.recv(length=self.serializer.required_len - len(data))
                (msg, data) = self.serializer.deserialize_msg(data)
            if msg.get("command") == b"ping":
                self.pong(msg["nonce"])  # Respond to ping immediately.
            elif msg.get("command") == b"version":
                self.version_reply(msg)  # Respond to version immediately.
            elif msg.get("command") == b"getheaders":
                self.headers([])  # Respond to getheaders immediately.
            msgs.append(msg)
        if len(msgs) > 0 and commands:
            msgs[:] = [m for m in msgs if m.get("command") in commands]
        return msgs

    def version_reply(self, version):
        # 70016 is the min. protocol version to accept sendaddrv2.
        if version.get("version", PROTOCOL_VERSION) >= 70016:
            # [sendaddrv2] + [verack] >>>
            msg = self.serializer.serialize_msg(
                command=b"sendaddrv2"
            ) + self.serializer.serialize_msg(command=b"verack")
        else:
            # [verack] >>>
            msg = self.serializer.serialize_msg(command=b"verack")
        self.send(msg)

    def set_min_version(self, version):
        self.serializer.protocol_version = min(
            self.serializer.protocol_version, version.get("version", PROTOCOL_VERSION)
        )

    def set_addrv2(self, sendaddrv2):
        self.serializer.addr_version = 2 if sendaddrv2 else None

    def handshake(self):
        # [version] >>>
        msg = self.serializer.serialize_msg(
            command=b"version", to_addr=self.to_addr, from_addr=self.from_addr
        )
        self.send(msg)

        # <<< [version 124 bytes] [sendaddrv2 24 bytes] [verack 24 bytes]
        gevent.sleep(1)
        version_msg = {}
        msgs = self.get_messages(commands=[b"version", b"sendaddrv2", b"verack"])
        if len(msgs) > 0:
            version_msg = next(
                (msg for msg in msgs if msg["command"] == b"version"), {}
            )
            self.set_min_version(version_msg)
            sendaddrv2_msg = next(
                (msg for msg in msgs if msg["command"] == b"sendaddrv2"), None
            )
            self.set_addrv2(sendaddrv2_msg)

        return version_msg

    def getaddr(self, block=True):
        # [getaddr] >>>
        msg = self.serializer.serialize_msg(command=b"getaddr")
        self.send(msg)

        # Caller should call get_messages separately.
        if not block:
            return None

        # <<< [addr]..
        gevent.sleep(1)
        msgs = self.get_messages(commands=[b"addr", b"addrv2"])
        return msgs

    def addr(self, addr_list):
        if self.serializer.addr_version == 2:
            # [addrv2] >>>
            msg = self.serializer.serialize_msg(command=b"addrv2", addr_list=addr_list)
        else:
            # [addr] >>>
            msg = self.serializer.serialize_msg(command=b"addr", addr_list=addr_list)
        self.send(msg)

    def ping(self, nonce=None):
        if nonce is None:
            nonce = random.getrandbits(64)

        # [ping] >>>
        msg = self.serializer.serialize_msg(command=b"ping", nonce=nonce)
        self.send(msg)

    def pong(self, nonce):
        # [pong] >>>
        msg = self.serializer.serialize_msg(command=b"pong", nonce=nonce)
        self.send(msg)

    def inv(self, inventory):
        # inventory = [(INV_TYPE, 'INV_HASH'),]
        # [inv] >>>
        msg = self.serializer.serialize_msg(command=b"inv", inventory=inventory)
        self.send(msg)

    def getdata(self, inventory):
        # inventory = [(INV_TYPE, 'INV_HASH'),]
        # [getdata] >>>
        msg = self.serializer.serialize_msg(command=b"getdata", inventory=inventory)
        self.send(msg)

        # <<< [tx] [block]..
        gevent.sleep(1)
        msgs = self.get_messages(commands=[b"tx", b"block"])
        return msgs

    def getblocks(self, block_hashes, last_block_hash=None):
        if last_block_hash is None:
            last_block_hash = b"0" * 64

        # block_hashes = ['BLOCK_HASH',]
        # [getblocks] >>>
        msg = self.serializer.serialize_msg(
            command=b"getblocks",
            block_hashes=block_hashes,
            last_block_hash=last_block_hash,
        )
        self.send(msg)

        # <<< [inv]..
        gevent.sleep(1)
        msgs = self.get_messages(commands=[b"inv"])
        return msgs

    def getheaders(self, block_hashes, last_block_hash=None):
        if last_block_hash is None:
            last_block_hash = b"0" * 64

        # block_hashes = ['BLOCK_HASH',]
        # [getheaders] >>>
        msg = self.serializer.serialize_msg(
            command=b"getheaders",
            block_hashes=block_hashes,
            last_block_hash=last_block_hash,
        )
        self.send(msg)

        # <<< [headers]..
        gevent.sleep(1)
        msgs = self.get_messages(commands=[b"headers"])
        return msgs

    def headers(self, headers):
        # headers = [{
        #   'version': VERSION,
        #   'prev_block_hash': PREV_BLOCK_HASH,
        #   'merkle_root': MERKLE_ROOT,
        #   'timestamp': TIMESTAMP,
        #   'bits': BITS,
        #   'nonce': NONCE
        # },]
        # [headers] >>>
        msg = self.serializer.serialize_msg(command=b"headers", headers=headers)
        self.send(msg)


def main():
    logformat = (
        "[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s "
        "(%(funcName)s) %(message)s"
    )
    logging.basicConfig(level="DEBUG", format=logformat)

    to_addr = ("127.0.0.1", PORT)

    version_msg = {}
    addr_msgs = []
    block_msgs = []

    conn = Connection(to_addr)
    try:
        logging.info(f"connecting to {to_addr}")
        conn.open()

        logging.info("handshake")
        version_msg = conn.handshake()

        logging.info("getaddr")
        addr_msgs = conn.getaddr()

        logging.info("getdata")
        block_msgs = conn.getdata(
            [
                (
                    2,
                    b"00000000000000000003d921bd82c8ab"
                    b"dc5665fd2460035b7a77005c3fd91276",
                )
            ]
        )

        logging.info("ping")
        conn.ping()

    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.error(f"{err}: {to_addr}")

    logging.info("close")
    conn.close()

    if version_msg:
        logging.info(f"[version_msg] user_agent={version_msg['user_agent']}")

    if addr_msgs:
        logging.info(f"[addr_msgs] addr_list[0]={addr_msgs[0]['addr_list'][0]}")

    if block_msgs:
        logging.info(
            f"[block_msgs] block={block_msgs[0]['block_hash']}"
            f" - tx_count={block_msgs[0]['tx_count']}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())

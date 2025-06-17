"""
IP packet:

4 bits: Version | 4 bits: Header Length | 8 bits: TOS* | 16 bits: Total Length
16 bits: Identification | 3 bits: Flags | 13 bits: Fragment offset
8 bites: TTL* | 8 bits: Protocol | 16 bits: Header checksum
32 bits: Source IP address
32 bits: Destination IP address
0 - 40 bits: Options
0 - 65,515 bits: Payload

* TOS - Type Of Service
* TTL - Time To Live
"""

import socket
import struct

from tcpython.packets.packet import Packet


class IP(Packet):
    PROTOCOL_NUM: dict = {
        1: socket.IPPROTO_ICMP,
        2: socket.IPPROTO_IGMP,
        6: socket.IPPROTO_TCP,
        17: socket.IPPROTO_UDP,
        132: socket.IPPROTO_SCTP
    }

    def __init__(self, src_ip, dst_ip, data_length, protocol):
        version = 4
        ihl = 5
        ver_ihl = (version << 4) + ihl
        tos = 0
        length = 20 + data_length
        id = 54321
        frag = 0
        ttl = 64
        proto = self.PROTOCOL_NUM.get(protocol)
        checksum = 0

        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        header = struct.pack("!BBHHHBBH4s4s",
                             ver_ihl, tos, length, id, frag,
                             ttl, proto, checksum, src, dst)

        checksum = self.compute_checksum(header)

        self.raw = struct.pack("!BBHHHBBH4s4s",
                               ver_ihl, tos, length, id, frag,
                               ttl, proto, checksum, src, dst)
        super().__init__(["IP"], self.raw)


    @staticmethod
    def compute_checksum(data):
        if len(data) % 2 == 1:
            data += b'\x00'

        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        while s > 0xFFFF:
            s = (s & 0xFFFF) + (s >> 16)

        return ~s & 0xFFFF

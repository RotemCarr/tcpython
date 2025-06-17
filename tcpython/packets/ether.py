"""
Ethernet Frame:

6 bytes: Destination MAC address | 6 bytes: Source MAC address | 2 bytes: Ether type
46-1500 bytes: Data
4 bytes CRC checksum **optional**
"""

import struct

from tcpython.packets.packet import Packet


class Ether(Packet):
    def __init__(self,
                 dst_mac: bytes,
                 src_mac: bytes,
                 ether_type: int,
                 ):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ether_type = ether_type
        self.raw = struct.pack("!6s6sH", dst_mac, src_mac, ether_type)
        super().__init__(["Ether"], self.raw)

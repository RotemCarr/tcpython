"""
UDP Packet:

16 bits: Source port | 16 bits: Destination port
16 bits: Length | 16 bits: Checksum
8-65535 bits: Data
"""

import struct

from tcpython.packets.packet import Packet


class UDP(Packet):
    def __init__(
        self,
        src_port: int,
        dst_port: int,
        src_ip: str,
        dst_ip: str,
        data: bytes,
        checksum: bool = True,
    ):
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = data
        self.length = 8 + len(data)
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        # UDP header fields (with checksum = 0 for now)
        header = struct.pack("!HHHH", src_port, dst_port, self.length, 0)

        if checksum:
            pseudo_header = self._build_pseudo_header()
            checksum_val = self._compute_checksum(pseudo_header + header + data)
            header = struct.pack("!HHHH", src_port, dst_port, self.length, checksum_val)

        self.raw = header + data
        super().__init__(["UDP"], self.raw)

    def _build_pseudo_header(self) -> bytes:
        # Convert IPs from string to bytes
        src_ip_bytes = struct.pack("!4B", *[int(b) for b in self.src_ip.split(".")])
        dst_ip_bytes = struct.pack("!4B", *[int(b) for b in self.dst_ip.split(".")])
        reserved = 0
        protocol = 17  # UDP
        udp_length = self.length

        return struct.pack("!4s4sBBH", src_ip_bytes, dst_ip_bytes, reserved, protocol, udp_length)

    @staticmethod
    def _compute_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"

        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        while s > 0xFFFF:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF


# packet = UDPPacket(
#     src_port=12345,
#     dst_port=80,
#     src_ip="192.168.1.10",
#     dst_ip="192.168.1.105",
#     data=b"Hello UDP",
#     checksum=True
# )
#
# print(packet.raw.hex())
# print(packet.raw)


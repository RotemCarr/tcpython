"""
16 bits: Source port | 16 bits: Dest port
32 bits: Sequence number
32 bits: Acknowledgement number
4 bits: Data offset | 4 bits: Reserved | 8 bits: *Flags | 16 bits: Window
16 bits: Checksum | 16 bits: Urgent pointer
(data_offset - 5) * 32 bits: Options
mtu - tcp_header bits: Data

*Flags - each flag is 1 bit:
    CWR
    ECE
    URG
    ACK
    PSH
    RST
    SYN
    FIN
"""

class TCPPacket:

    @staticmethod
    def _pad(bits: str, padding: int):
        return bits.zfill(padding)

    def __init__(
            self,
            source_port,
            dst_port,
            sequence_number,
            ack_number,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_pointer,
            options,
            data
    ):
        src_port_bits = bin(source_port)[2:]
        dst_port_bits = bin(dst_port)[2:]
        sequence_number_bits = bin(sequence_number)[2:]
        pass

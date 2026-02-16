import socket
import struct

from tcpython.packets import Ether, IP
from tcpython.packets.udp import UDP


def send_raw_udp(udp_packet, dst_ip):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))  # Your interface
    _packet = udp_packet.raw
    print(_packet)
    s.sendto(_packet, (dst_ip, 0))


def receive_response(timeout=2, expected_dst_port=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(timeout)

    try:
        while True:
            data, addr = s.recvfrom(65535)
            ip_header = data[:20]
            icmp_header = data[20:28]

            icmp_type, code, checksum, identifier, sequence = struct.unpack("!BBHHH", icmp_header)

            print(f"[+] ICMP from {addr[0]}: type={icmp_type}, code={code}")

            if icmp_type == 3 and code == 3:
                # Parse embedded IP header (bytes 28:48) and UDP header (bytes 48:56)
                embedded_ip = data[28:48]
                embedded_udp = data[48:56]

                ver_ihl, tos, total_len, ident, frag, ttl, proto, checksum, src_ip_raw, dst_ip_raw = struct.unpack("!BBHHHBBH4s4s", embedded_ip)
                src_ip = socket.inet_ntoa(src_ip_raw)
                dst_ip = socket.inet_ntoa(dst_ip_raw)
                src_port, dst_port, _, _ = struct.unpack("!HHHH", embedded_udp)

                print(f"  ↪ Embedded UDP packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}")

                if expected_dst_port is None or dst_port == expected_dst_port:
                    print("💥 ICMP Destination Unreachable — Port Unreachable (expected match)")
                    break
                else:
                    print("⚠️ ICMP doesn't match expected port")

    except socket.timeout:
        print("⌛ No ICMP response received")
    finally:
        s.close()

eth = Ether(dst_mac=b"\xff\xff\xff\xff\xff\xff", src_mac=b"\xff\xff\xff\xff\xff\xff", ether_type=2048)
ip = IP("192.168.1.10", "192.168.1.20", 30, 17)
udp = UDP(
    src_port=12345,
    dst_port=1234,
    src_ip="192.168.1.219",
    dst_ip="192.168.1.104",
    data=b"Hello, UDP",
    checksum=True
)

packet = eth / ip / udp

def receive_udp_on_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    s.settimeout(3)  # or None for blocking
    try:
        data, addr = s.recvfrom(1024)
        print(f"✅ Received reply from {addr}: {data}")
    except socket.timeout:
        print("⌛ No reply received")
    finally:
        s.close()

send_raw_udp(packet, udp.dst_ip)
# receive_response(timeout=3, expected_dst_port=1234)
receive_udp_on_port(12345)
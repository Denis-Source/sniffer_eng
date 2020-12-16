"""Sniffer

This program is designed to capture all Internet Frames that are used for TCP/IP.
Libraries that are used:
    socket : used for work with the program interfaces;
    struct : used for frame decoding;
    time : used for frame timestamp.
Consists of the following classes:
    IPv4Packet;
    TCPPacket;
    UDPPacket;
    Sniffer.
"""

from sniffer import Sniffer

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.sniff(is_inf=True, to_print=True)

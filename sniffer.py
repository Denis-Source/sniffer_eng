import socket

from packets.ipv4 import IPv4Packet
from packets.udp import UDPPacket
from packets.tcp import TCPPacket


class Sniffer(object):
    """
    Sniffer class
    Captures IPv4 frames

    Attributes:
        host : IPv4 address used for frame capturing; str;
        host_name : name of the computer used for frame capturing; str;
        socket : socket library class;

    Methods:
        sniff_once
        sniff
        save_packets
        save_packets

    Static methods:
        get_mac_addr
        enthernet_frame
    """

    def __init__(self, ip="AUTO"):
        if ip == "AUTO":
            self.host = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
            self.host_name = socket.gethostbyname_ex(socket.gethostname())[0]
        else:
            self.host = ip
            self.host_name = "unknown"
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind((self.host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    @staticmethod
    def get_mac_addr(bytes_addr):
        """
        Converts bytes array into MAC address (AA:BB:CC:DD:EE)

        :param bytes_addr: bytes
        :return: str
        """
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()

    @staticmethod
    def enthernet_frame(data):
        """
        Converts bytes array into source MAC-address, destination MAC-address and IPv4 protocol

        :param data: bytes
        :return: str, str, int, bytes
        """
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return Sniffer.get_mac_addr(dest_mac), Sniffer.get_mac_addr(src_mac), socket.htons(proto), data[:14]

    def sniff_once(self, to_print):
        """
        Captures a single frame
        Returns IPv4Packet class frame (
                                        If it`s a TCP - returns UDPPacket class frame
                                        If it`s a UDP - returns TCPPacket class frame
                                        )

        :param to_print: bool выводить ли пакет на экран
        :return: IPv4Packet
        """
        packet, addr = self.socket.recvfrom(65536)
        datagram = IPv4Packet(packet)

        if datagram.proto_str == "TCP":
            datagram = TCPPacket(packet)
        if datagram.proto_str == "UDP":
            datagram = UDPPacket(packet)
        if to_print:
            print(datagram)
        return datagram

    def sniff(self, num_of_packets=1, is_inf=False, to_print=False):
        """
        Captures frames

        :param num_of_packets: int amount of the frames that will be captured
        :param is_inf: bool to capture frames infinitely
        :param to_print: bool to print captured frames
        :return: None
        """
        if to_print:
            print(f"Sniffing {self.host_name} at {self.host}:")
        if is_inf:
            while True:
                self.sniff_once(to_print)
        else:
            for i in range(num_of_packets):
                self.sniff_once(to_print)

    def save_packets(self, file_name="test.txt", num_of_packets=1, is_inf=False, to_print=False):
        """
        Captures frames and stores them into a specified file

        :param file_name: str name of the file to store into
        :param num_of_packets: int amount captured frames
        :param is_inf: bool захватывать ли to capture frames infinitely
        :param to_print: bool to print packets
        :return: None
        """
        if to_print:
            print(f"Saving packets from {self.host_name} at {self.host}:")
        file = open(file_name, "w")
        file.write(f"Saved packets from {self.host_name} at {self.host}:\n")
        file.close()
        if is_inf:
            while True:
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()

        else:
            for i in range(num_of_packets):
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()

import socket
import struct
import re

from frames.ipv4 import IPv4Frame
from frames.udp import UDPFrame
from frames.tcp import TCPFrame


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
        save_frames
        seek_domains

    Static methods:
        get_mac_addr
        ethernet_frame
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
        Converts a byte array into a MAC address (AA:BB:CC:DD:EE)

        :param bytes_addr: bytes
        :return: str
        """
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()

    @staticmethod
    def ethernet_frame(data):
        """
        Converts a byte array into a MAC-address source, MAC-address destination and IPv4 protocol

        :param data: bytes
        :return: str, str, int, bytes
        """
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return Sniffer.get_mac_addr(dest_mac), Sniffer.get_mac_addr(src_mac), socket.htons(proto), data[:14]

    def sniff_once(self, to_print):
        """
        Captures a single frame
        Returns a IPv4Frame class frame (
            If it`s a TCP - returns UDPFrame class frame
            If it`s a UDP - returns TCPFrame class frame
                                        )

        :param to_print: bool
        :return: IPv4Frame
        """
        frame, addr = self.socket.recvfrom(65536)
        datagram = IPv4Frame(frame)

        if datagram.proto_str == "TCP":
            datagram = TCPFrame(frame)
        if datagram.proto_str == "UDP":
            datagram = UDPFrame(frame)
        if to_print:
            print(datagram)
        return datagram

    def sniff(self, num_of_frames=1, is_inf=False, to_print=False):
        """
        Captures frames

        :param num_of_frames: int amount of frames that will be captured
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
            for i in range(num_of_frames):
                self.sniff_once(to_print)

    def save_frames(self, file_name="sniff.txt", num_of_frames=1, is_inf=False, to_print=False):
        """
        Captures frames and saves them in a specified file

        :param file_name: str name of the file to store into
        :param num_of_frames: int amount captured frames
        :param is_inf: bool to capture frames infinitely
        :param to_print: bool to print frames
        :return: None
        """
        if to_print:
            print(f"Saving frames from {self.host_name} at {self.host}:")
        file = open(file_name, "w")
        file.write(f"Saved frames from {self.host_name} at {self.host}:\n")
        file.close()
        if is_inf:
            while True:
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()

        else:
            for i in range(num_of_frames):
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()

    def seek_domains(self):
        """
        Tries to find a domain in DNS request
        Parses frame payload to find URLs
        Prints the on the screen

        :return: None
        """
        while True:
            ascii_payload = IPv4Frame.bytes_to_ascii(self.sniff_once(False).payload)
            exp = re.compile(r"[a-z]{5,}\.[a-z]{2,}")
            res = exp.findall(ascii_payload)
            if res:
                print(res)

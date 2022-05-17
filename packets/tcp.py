import struct

from packets.ipv4 import IPv4Packet


class TCPPacket(IPv4Packet):
    """
    TCP packet class.
    Arguments:
    raw_data - bytes input; bytes;
    Inherits IPv4Packet class;
    Inherited Attributes:
        id_counter : counter variable; tracks how many of the packets were created; int;
        proto : protocol version; int;
        proto_str : protocol version name; str;
        ttl : time to live; int;
        src : packet source; IPv4 format; str;
        target : packet destination; IPv4 format; str;
        time : packet capture time; asctime format; str;
        data : bytes array of the packet; bytes;
        payload : data that are stored in the packet as a payload; bytes.

    Attributes:
        payload : payload data; bytes;
        src_port : source port; int;
        dest_port : destination port; int;
        sequence
        acknowledgement
        Flags:
            flag_urg
            flag_ack
            flag_psh
            flag_rst
            flag_syn
            flag_fin
    """

    def __init__(self, raw_data):
        IPv4Packet.__init__(self, raw_data)
        IPv4Packet.id_counter -= 1
        (self.src_port, self.dest_port, self.sequence, self.acknowledgement, offset_reserved_flags) = struct.unpack(
            "! H H L L H",
            raw_data[:14])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.payload = raw_data[self.offset:]

    def __str__(self):
        """
        Converts packet information into a readable format.

        Has the following format:
            Ethernet Packet: #1
            Time: Tue Dec 8 00:01:28 2019
            TTL: 57 Protocol: TCP
            Source: 255.255.255.255:80, Destination: 192.168.0.0:65535
            Flags: urg: 0, ack: 1, fsh: 1, rst 1, syn: 1, fin: 1
            Data:
            17 03 03 00 27 73 02 12 E6 F3 6F 3E 1E 43 F9 7B 1B C7 9C D6 35
        :return: str
        """

        return f"\nEthernet Packet: #{self.id_counter}\nTime: {self.time}\n" \
               f"TTL: {self.ttl} Protocol: {self.proto_str}\n" \
               f"Source: {self.src}:{self.src_port}, Destination: {self.target}:{self.dest_port}\n" \
               f"Flags: urg: {self.flag_urg}, ack: {self.flag_ack}, fsh: {self.flag_psh}, " \
               f"rst {self.flag_rst}, syn: {self.flag_rst}, fin: {self.flag_fin}\n" \
               f"Data: \n{IPv4Packet.bytes_to_hex(self.payload)}"

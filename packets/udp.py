import struct

from packets.ipv4 import IPv4Packet


class UDPPacket(IPv4Packet):
    """
    UDP frame class.
    Arguments:
    raw_data - bytes input; bytes;
    Inherits IPv4Packet class.
    Inherited Attributes:
        id_counter : counter variable; tracks how many of the frames were created; int;
        proto : protocol version; int;
        proto_str : protocol version name; str;
        ttl : time to live; int;
        src : frame source; IPv4 format; str;
        target : frame destination; IPv4 format; str;
        time : frame capture time; asctime format; str;
        data : bytes array of the frame; bytes;
        payload : payload data; bytes;

    Attributes:
        src_port : source port; int;
        dest_port : destination port; int;
        size : size of the payload in bites; bytes;
    """

    def __init__(self, raw_data):
        IPv4Packet.__init__(self, raw_data)
        IPv4Packet.id_counter -= 1
        self.src_port, self.dest_port, self.size = struct.unpack("! H H 2x H", raw_data[:8])

    def __str__(self):
        """
        Converts packet information into readable format

        Has the following format:
            Ethernet Frame: #1 	Time: Tue Dec 0 00:01:28 2019
            TTL: 57 Protocol: TCP
            Source: 162.159.130.234:17664, Destination: 192.168.0.104:84
            Flags: urg: 0, ack: 1, fsh: 1, rst 1, syn: 1, fin: 1
            Data:
            17 03 03 00 27 73 02 12 E6 F3 6F 3E 1E 43 F9 7B 1B C7 9C

        :return: str
        """

        return f"\nEthernet Packet #{self.id_counter} \tTime: {self.time}\n" \
               f"TTL: {self.ttl} Protocol: {self.proto_str}\n" \
               f"Source: {self.src}:{self.src_port}, Destination: {self.target}:{self.dest_port}\n" \
               f"Data: \n{IPv4Packet.bytes_to_hex(self.payload)}"

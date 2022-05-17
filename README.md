# sniffer_eng
Captures IPV4 packets, displays its contents and information

## Installation

Clone repository:
```shell
git clone https://github.com/Denis-Source/sniffer_eng
cd sniffer_eng
```
The application does not use any of the 3rd party modules and relies entirely on builtins libraries:
- socket (http\s interfaces);
- struct: (byte packet decoding);
- time.

To start the application, simply run `main.py` file:
```shell
python main.py
```
> **IT IS IMPORTANT** to run the application with administrative privileges!

## Showcase
When run in the default configuration, the application has the following output:
```shell
Sniffing DESKTOP-123ABCDE at 192.168.1.99:

Ethernet Packet: #1
Time: Tue May 17 14:39:44 2020
TTL: 128 Protocol: TCP
Source: 192.168.1.99:12345, Destination: 8.8.8.8:53
Flags: urg: 1, ack: 0, fsh: 1, rst 0, syn: 0, fin: 0
Data: 
97 2F 00 56 7C BF 24 9E 3D 19 C1 46 15 95 93 16 B7 16 E4 15 D0 F0 7E E4 1B E0 86 06 C8 53 AC 2D 5C 14 FF 0A 8E C2 A0 87 
39 F4 10 A8 59 AC 30 7A FF 4A 42 09 DF 59 EA AD 20 EB 9C 18 35 67 66 D4 0C 32 85 29 C0 87 F9 EC 24 1F F7 4E 42 A0 FA F7 
2B AF 1E 27 10 C1 33 CD F1 9D 1D F8 68 66 24 A8 41 5E 33 14 06 3C F5 B4 3F A8 06 26 2C D8 B4 8F 52 FA 09 CA 1C ED 20 E0 
7D F4 89 FE C6 18 DE 09 D1 
```

The output has the following information:
- Packet serial number: `Ethernet Packet: #1`;
- [ASCII time format](https://docs.python.org/3/library/time.html#time.asctime): `Time: Tue May 17 14:39:44 2020`;
- Time to live and protocol name: `TTL: 128 Protocol: TCP`;
- Flag information: `Flags: urg: 1, ack: 0, fsh: 1, rst 0, syn: 0, fin: 0`.

For an example, there are the following flags:
- The urgent flag (sets the priority of the packet);
- The acknowledgment flag is used to acknowledge the successful receipt of a packet;
- The push flag is somewhat similar to the URG flag and tells the receiver to process these packets as they are received instead of buffering them;
- The reset flag gets sent from the receiver to the sender when a packet is sent to a particular host that was not expecting it;
- The synchronisation flag is used to initiate a connection between two hosts. It should be set only in the first packet of both the initiator and the receiver;
- The finished flag means there is no more data from the sender. Therefore, it is used in the last packet sent from the sender.

Data is displayed in hexadecimal format:
```
97 2F 00 56 7C BF 24 9E 3D 19 C1 46 1...
```

## Class methods

The main class, `Sniffer` has the following listening methods:
Returns the first captured packet:
```python
sniff_once()
```
`to_print` flag to display captured packet in the console.

Captures wether the specified amount of packets or indefenetly:
```python
sniff()
```
`num_of_packets` desired number of captured packets;
`to_print` flag to display the captured packet on the console;
`is_inf` flag to capture packets indefinitely.

Saves packets in the specified file:
```python
save_packets()
```

`file_name` name of the file to store the captured packets;
`num_of_packets` desired number of captured packets;
`to_print` flag to display the captured packet on the console;
`is_inf` flag to capture packets indefinitely.

Displays visited urls:
```python
seek_domains()
```

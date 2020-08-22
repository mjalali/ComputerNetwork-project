import socket
from struct import *
from binascii import *
from time import *


class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Ethernet:
    def __init__(self, des_mac=0, source_mac=0, protocol=0):
        self.des_mac = des_mac
        self.source_mac = source_mac
        self.protocol_num = protocol
        self.data = ""

    def parser(self, data):
        self.des_mac, self.source_mac, self.protocol_num = unpack('!6s6s2s', data[:14])
        self.des_mac = str(hexlify(self.des_mac).decode("utf-8"))
        self.source_mac = str(hexlify(self.source_mac).decode("utf-8"))
        self.protocol_num = str(hexlify(self.protocol_num).decode("utf-8"))
        self.data = data[14:]
        return [self.get_mac_addr(self.des_mac), self.get_mac_addr(self.source_mac), self.protocol_num]

    def get_mac_addr(self, data):
        return data[0:2] + ":" + data[2:4] + ":" + data[4:6] + ":" + data[6:8] + ":" + data[8:10] + ":" + data[10:12]

    def get_dest_mac(self):
        return self.get_mac_addr(self.des_mac)

    def get_src_mac(self):
        return self.get_mac_addr(self.source_mac)

    def get_data(self):
        return self.data


class Ipv4:
    def __init__(self, version=4, ihl=5, type_of_service=0, total_len=40, id=54321, flags=0, offset=0, ttl=255,
                 protocol=socket.IPPROTO_TCP, checksum=10, src_ip='', dst_ip=''):
        self.version = version
        self.ihl = ihl
        self.tos = type_of_service
        self.total_length = total_len
        self.id = id
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.data = ""

    def parser(self, data):
        version_ihl, Tos, total_len, ID, flags_offset, ttl, prtcl, chcksum, src, dst = unpack('!BBHHHBBH4s4s',
                                                                                              data[:20])
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0xF) * 4
        self.tos = Tos
        self.total_length = total_len
        self.id = ID
        flags = flags_offset >> 13
        self.flags = {"DF": (flags >> 1) & 0x01, "MF": flags & 0x01}
        self.offset = flags_offset & 0x1FFF
        self.ttl = ttl
        self.protocol = prtcl
        self.checksum = chcksum
        self.src_ip = socket.inet_ntoa(src)
        self.dst_ip = socket.inet_ntoa(dst)
        self.data = data[20:]
        return [self.version, self.ihl, self.tos, self.total_length, self.id, self.flags, self.offset, self.ttl,
                self.protocol, self.checksum, self.src_ip, self.dst_ip]

    def header_packer(self):
        # calculate checksum here
        return pack('!BBHHHBBH4s4s', ((self.version << 4) + self.ihl), self.tos, self.total_length, self.id, self.flags,
                    self.ttl, self.protocol, self.checksum, bytes(map(int, self.src_ip.split('.'))),
                    bytes(map(int, self.dst_ip.split('.'))))

class ICMP:
    def __init__(self, type_=0, code=0, checksum=0):
        self.type = type_
        self.code = code
        self.checksum = checksum
        self.data = ""

    def parser(self, data):
        self.type, self.code, self.checksum = unpack('!BBH', data[:4])
        return [self.type, self.code, self.checksum]


class TCP:
    def __init__(self, src_port=0, dst_port=0, seq_num=0, ack_num=0, flags=0, window_size=1024, checksum=0,
                 urg=0):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = 0
        if flags == 0:
            self.flags = {"NS": 0, "CWR": 0, "ECE": 0, "URG": 0, "ACK": 0, "PSH": 0, "RST": 0, "SYN": 0, "FYN": 0}
        else:
            self.flags = flags
        self.window_size = window_size
        self.checksum = checksum
        self.urg = urg
        self.data = ""

    def calculate_checksum(self, data):
        s = 0
        for i in range(0, len(data), 2):
            x = (data[i] << 8) + data[i + 1]
            s += x
        carry = s >> 16
        s = carry + (s & 0xFFFF)
        s = (~s) & 0xFFFF
        return s

    def parser(self, data):
        self.src_port, self.dst_port, self.seq_num, self.ack_num, flags, self.window_size, self.checksum, self.urg = \
            unpack('!HHIIHHHH', data[:20])
        data_offset = (flags >> 12) * 4
        self.data = data[data_offset:]
        reserved = (flags >> 9) & 0x07
        NS = (flags >> 8) & 0x01
        CWR = (flags >> 7) & 0x01
        ECE = (flags >> 6) & 0x01
        URG = (flags >> 5) & 0x01
        ACK = (flags >> 4) & 0x01
        PSH = (flags >> 3) & 0x01
        RST = (flags >> 2) & 0x01
        SYN = (flags >> 1) & 0x01
        FYN = flags & 0x01
        self.flags = {"NS": NS, "CWR": CWR, "ECE": ECE, "URG": URG, "ACK": ACK, "PSH": PSH, "RST": RST, "SYN": SYN,
                      "FYN": FYN}
        return [self.src_port, self.dst_port, self.seq_num, self.ack_num, data_offset, reserved, self.flags,
                self.window_size, self.checksum, self.urg]

    def header_packer(self):
        concat_flags = (self.flags["CWR"] << 7) + (self.flags["ECE"] << 6) + (self.flags["URG"] << 5) + (
                self.flags["ACK"] << 4) + (self.flags["PSH"] << 3) + (self.flags["RST"] << 2) + \
                       (self.flags["SYN"] << 1) + (self.flags["FYN"])
        self.data_offset = 5 << 4
        return pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_num, self.ack_num, self.data_offset,
                    concat_flags, self.window_size, self.checksum, self.urg)


class UDP:
    def __init__(self, src_port=0, dst_port=0, length=0, checksum=0):
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.checksum = checksum
        self.data = ""

    def parser(self, data):
        self.src_port, self.dst_port, self.length, self.checksum = unpack('!HHHH', data[:8])
        self.data = data[8:]
        return [self.src_port, self.dst_port, self.length, self.checksum]


class ARP:
    def __init(self, HTYPE=0, PTYPE=0, HLEN=0, PLEN=0, OP=0, SHA=0, SPA=0, THA=0, TPA=0):
        self.HTYPE = HTYPE
        self.PTYPE = PTYPE
        self.HLEN = HLEN
        self.PLEN = PLEN
        self.OP = OP
        self.SHA = SHA
        self.SPA = SPA
        self.THA = THA
        self.TPA = TPA
        self.data = ""

    def get_mac_addr(self, data):
        return data[0:2] + ":" + data[2:4] + ":" + data[4:6] + ":" + data[6:8] + ":" + data[8:10] + ":" + data[10:12]

    def parser(self, data):
        self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.OP, self.SHA, SPA, self.THA, TPA = \
            unpack('!HHBBH6s4s6s4s', data[:28])
        self.SPA = socket.inet_ntoa(SPA)
        self.TPA = socket.inet_ntoa(TPA)
        self.data = data[28:]
        self.SHA = str(hexlify(self.SHA).decode("utf-8"))
        self.THA = str(hexlify(self.THA).decode("utf-8"))
        return [self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.OP, self.get_mac_addr(self.SHA), self.SPA,
                self.get_mac_addr(self.THA), self.TPA]


class DNS:
    def __init__(self, ID=0, flags=0):
        self.ID = ID
        self.flags = flags
        self.data = ""

    def parser(self, data):
        ID, flags = unpack('!HH', data[:4])
        QR = flags >> 15
        Opcode = (flags >> 11) & 0xFF
        AA = (flags >> 10) & 0x01
        TC = (flags >> 9) & 0x01
        RD = (flags >> 8) & 0x01
        RA = (flags >> 7) & 0x01
        rcode = flags & 0xFF
        flags = {"QR": QR, "Opcode": Opcode, "AA": AA, "TC": TC, "RD": RD, "RA": RA, "rcode": rcode}
        self.data = data[4:]
        return [ID, flags]


class HTTP:
    def __init__(self):
        pass

    def parser(self, data):
        temp = str(data.decode('unicode_escape'))
        i = temp.rfind("\r\n\r\n")
        if 0 < i < (len(temp) - 5):
            temp = temp[:i] + "\r\n" + "HTTP data" + temp[i:]
        return [temp]


class Pcap:
    def __init__(self, name, type=1):
        self.pcap_file = open(name, 'wb')
        self.pcap_file.write(pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, type))

    def pcap_write(self, data):
        t_sec, t_usec = map(int, str(time()).split('.'))
        self.pcap_file.write(pack('@IIII', t_sec, t_usec, len(data), len(data)))
        self.pcap_file.write(data)

    def pcap_close(self):
        self.pcap_file.close()


def main():
    count = 0
    name = str(input("Enter  file name:\n"))
    packet_num = int(input("Enter number of packets:\n"))
    pcap_file = Pcap(name)
    pcap_flag = 1
    ethernet1 = Ethernet()
    ip1 = Ipv4()
    tcp1 = TCP()
    udp1 = UDP()
    http1 = HTTP()
    dns1 = DNS()
    arp1 = ARP()
    icmp1 = ICMP()
    while True:
        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        data, addr = connection.recvfrom(65535)
        count = count + 1
        print("\n\nPacket_num:", count)
        if count < packet_num and pcap_flag == 1:
            pcap_file.pcap_write(data)
        elif count == packet_num and pcap_flag == 1:
            pcap_file.pcap_close()
            print("File Closed.\n")
            pcap_flag = 0
            break
        print(150 * '-')
        ethernet_header = ethernet1.parser(data)
        print(Bcolors.FAIL + "Ethernet Frame:\n\r-Destination:", ethernet_header[0], ", Source:",
              ethernet_header[1], ", Protocol number:", ethernet_header[2], "\n" + Bcolors.ENDC)
        transport_flag = 0
        if int(ethernet_header[2], 16) == 0x0806:  # ARP packet
            network_header = arp1.parser(ethernet1.data)
            print(Bcolors.OKGREEN + "ARP Packet:\n\r-Hardware:", network_header[0], ", Protocol:", network_header[1],
                  ", Header Length:", network_header[2], ", Protocol Length:", network_header[3], ", Operation:",
                  network_header[4], ", Sender MAC Addr:", network_header[5], ", Sender IPAddr:", network_header[6],
                  ", Target MAC Addr:", network_header[7], ", Target IP Addr:", network_header[8], "\n\rARP Data:\n\r",
                  str(arp1.data) + Bcolors.ENDC)
        elif int(ethernet_header[2], 16) == 0x0800:  # IPV4 packet
            network_header = ip1.parser(ethernet1.data)
            print(Bcolors.OKBLUE + "IPv4 Datagram:\n\r-Version:", network_header[0], ",Header Length:",
                  network_header[1],
                  ", Type of Service:", network_header[2], ", Total Length:", network_header[3], ", Identification",
                  network_header[4], ", Flags:", network_header[5], ", Data Offset:", network_header[6],
                  ", Time To Live:", network_header[7], ",Protocol:", network_header[8], ", Checksum:",
                  network_header[9], ", Source IP Addr:", network_header[10], ", Destination IP Addr:",
                  str(network_header[11]) + Bcolors.ENDC)
            if network_header[8] == 1:  # ICMP packet
                transport_header = icmp1.parser(ip1.data)
                print(Bcolors.UNDERLINE + "ICMP Packet:\n\r-Type:", transport_header[0], ", Code:",
                      transport_header[1], ", Checksum:", transport_header[2], "\n\rICMP Data:",
                      str(icmp1.data) + Bcolors.ENDC)

            elif network_header[8] == 6:  # TCP
                transport_header = tcp1.parser(ip1.data)
                print(Bcolors.BOLD + "\nTCP Segment:\n\r-Source Port:", transport_header[0], ", Destination Port:",
                      transport_header[1],
                      ", Sequence Number:", transport_header[2], ", Acknowledgement Number:", transport_header[3],
                      ", Data Offset:", transport_header[4], ", Reserved 3 bits:", bin(transport_header[5]),
                      "Flags: ", transport_header[6], ", Windows Size:", transport_header[7], ", Checksum:",
                      transport_header[8], ", Urgent Pointer:", transport_header[9],
                      "\n\r TCP data:", str(tcp1.data) + Bcolors.ENDC)
                transport_flag = 1
            elif network_header[8] == 17:  # UDP
                transport_header = udp1.parser(ip1.data)
                print(Bcolors.BOLD + "UDP Segment:\n\r-Source Port:", transport_header[0], ", Destination Port:",
                      transport_header[1],
                      ", Header Length:", transport_header[2], ", Checksum:", transport_header[3],
                      "\n\r UDP data:", str(udp1.data) + Bcolors.ENDC)
                transport_flag = 1
            else:
                print("IPv4 Datagram Data:\n\r", ip1.data)


if __name__ == "__main__":
    main()

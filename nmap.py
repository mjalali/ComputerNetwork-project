#!/usr/bin/python3
from wireshark import Ethernet
from wireshark import Ipv4
from wireshark import ICMP
from wireshark import TCP
import sys
import getopt
import socket
import time
from struct import *
from threading import Thread


src_addr = '192.168.1.66'


def connect_scan(ip, start_port, end_port, delay=4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    open_ports = []
    for i in range(start_port, end_port + 1):
        s.settimeout(1)
        try:
            s.connect((ip, i))
        except():
            s.close()
            continue
        open_ports.append(i)
        s.close()
        time.sleep(delay)
    return open_ports


ack_list = []


def recv_ack_scan(ip, length, delay):
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ip1 = Ipv4()
    tcp1 = TCP()
    start_time = int(time.time())
    while True:
        if int(delay * length) < int(time.time()) - start_time:
            break
        data, addr = connection.recvfrom(65535)
        ipv4_header = ip1.parser(data[14:])
        if (ipv4_header[10] == ip) & (ipv4_header[11] == src_addr) & (ipv4_header[8] == socket.IPPROTO_TCP):
            tcp_header = tcp1.parser(ip1.data)
            if tcp_header[6]["RST"] == 1:
                ack_list.append(tcp1.src_port)


def send_ack_scan(ip, ports, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while len(ports) > 0:
        dest_port = ports.pop()
        ip1 = Ipv4(src_ip=src_addr, dst_ip=ip)
        tcp1 = TCP(1234, dest_port)
        tcp1.flags["ACK"] = 1
        place_holder = 0
        temp_header = pack('!4s4sBBH', bytes(map(int, ip1.src_ip.split('.'))), bytes(map(int, ip1.dst_ip.split('.'))),
                           place_holder, ip1.protocol, 20)
        temp_header = temp_header + tcp1.header_packer()
        tcp_checksum = tcp1.calculate_checksum(temp_header)
        print(f"{temp_header} -> {tcp_checksum}")
        concat_flags = (tcp1.flags["CWR"] << 7) + (tcp1.flags["ECE"] << 6) + (tcp1.flags["URG"] << 5) + \
                       (tcp1.flags["ACK"] << 4) + (tcp1.flags["PSH"] << 3) + (tcp1.flags["RST"] << 2) + \
                       (tcp1.flags["SYN"] << 1) + (tcp1.flags["FYN"])
        offset = 5 << 4
        tcp_header = pack('!HHLLBBHHH', tcp1.src_port, tcp1.dst_port, tcp1.seq_num, tcp1.ack_num, offset,
                          concat_flags, tcp1.window_size, tcp_checksum, tcp1.urg)
        datagram = ip1.header_packer() + tcp_header
        sock.sendto(datagram, (ip, 0))
        time.sleep(delay)


def ack_scan(ip, start_port, end_port, delay=4):
    start_time = int(time.time())
    recv_thread = Thread(target=recv_ack_scan, args=(ip, end_port-start_port+1, delay))
    recv_thread.start()
    queue = []
    for i in range(start_port, end_port+1):
        queue.append(i)
    q = [[] for _ in range(6)]
    while len(queue) > 0:
        for i in range(0, 6):
            if len(queue) > 0:
                q[i].append(queue.pop())
            else:
                break
    send_threads = []
    for i in range(0, 6):
        temp = Thread(target=send_ack_scan, args=(ip, q[i], delay))
        send_threads.append(temp)
        temp.start()
    for i in send_threads:
        i.join()
    recv_thread.join()
    ack_list.sort()
    temp_set = set(ack_list)
    for i in temp_set:
        print(f"port {i} is unfiltered")


syn_dict = {}


def recv_syn_scan(ip, length, delay):
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ip1 = Ipv4()
    tcp1 = TCP()
    icmp1 = ICMP()
    start_time = int(time.time())
    while True:
        if int(delay * length) < int(time.time()) - start_time:
            break
        data, addr = connection.recvfrom(65535)
        ipv4_header = ip1.parser(data[14:])
        if (ipv4_header[10] == ip) & (ipv4_header[11] == src_addr):
            if ipv4_header[8] == socket.IPPROTO_TCP:
                tcp_header = tcp1.parser(ip1.data)
                if tcp_header[6]["RST"] == 1:
                    if syn_dict.get(tcp1.src_port) is None:
                        syn_dict[tcp1.src_port] = 'closed'
                if tcp_header[6]["SYN"] == 1 or tcp_header[6]["ACK"] == 1:
                    if syn_dict.get(tcp1.src_port) is None:
                        syn_dict[tcp1.src_port] = 'open'


def send_syn_scan(ip, ports, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while len(ports) > 0:
        dest_port = ports.pop()
        ip1 = Ipv4(src_ip=src_addr, dst_ip=ip)
        tcp1 = TCP(1235, dest_port)
        tcp1.flags["SYN"] = 1
        place_holder = 0
        temp_header = pack('!4s4sBBH', bytes(map(int, ip1.src_ip.split('.'))), bytes(map(int, ip1.dst_ip.split('.'))),
                           place_holder, ip1.protocol, 20)
        temp_header = temp_header + tcp1.header_packer()
        tcp_checksum = tcp1.calculate_checksum(temp_header)
        print(f"{temp_header} -> {tcp_checksum}")
        concat_flags = (tcp1.flags["CWR"] << 7) + (tcp1.flags["ECE"] << 6) + (tcp1.flags["URG"] << 5) + \
                       (tcp1.flags["ACK"] << 4) + (tcp1.flags["PSH"] << 3) + (tcp1.flags["RST"] << 2) + \
                       (tcp1.flags["SYN"] << 1) + (tcp1.flags["FYN"])
        offset = 5 << 4
        tcp_header = pack('!HHLLBBHHH', tcp1.src_port, tcp1.dst_port, tcp1.seq_num, tcp1.ack_num, offset,
                          concat_flags, tcp1.window_size, tcp_checksum, tcp1.urg)
        datagram = ip1.header_packer() + tcp_header
        sock.sendto(datagram, (ip, 0))
        time.sleep(delay)


def syn_scan(ip, start_port, end_port, delay=4):
    start_time = int(time.time())
    recv_thread = Thread(target=recv_syn_scan, args=(ip, end_port - start_port + 1, delay))
    recv_thread.start()
    queue = []
    for i in range(start_port, end_port + 1):
        queue.append(i)
    q = [[] for _ in range(6)]
    while len(queue) > 0:
        for i in range(0, 6):
            if len(queue) > 0:
                q[i].append(queue.pop())
            else:
                break
    send_threads = []
    for i in range(0, 6):
        temp = Thread(target=send_syn_scan, args=(ip, q[i], delay))
        send_threads.append(temp)
        temp.start()
    for i in send_threads:
        i.join()
    recv_thread.join()
    for i in range(start_port, end_port+1):
        if syn_dict.get(i) is not None:
            print(f"port {i} is {syn_dict[i]}")
        else:
            print(f"port {i} is filtered")


fyn_list = []


def recv_fyn_scan(ip, length, delay):
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ip1 = Ipv4()
    tcp1 = TCP()
    start_time = int(time.time())
    while True:
        if int(delay * length) < int(time.time()) - start_time:
            break
        data, addr = connection.recvfrom(65535)
        ipv4_header = ip1.parser(data[14:])
        if (ipv4_header[10] == ip) & (ipv4_header[11] == src_addr) & (ipv4_header[8] == socket.IPPROTO_TCP):
            tcp_header = tcp1.parser(ip1.data)
            if tcp_header[6]["RST"] == 1:
                fyn_list.append(tcp1.src_port)  # closed


def send_fyn_scan(ip, ports, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while len(ports) > 0:
        dest_port = ports.pop()
        ip1 = Ipv4(src_ip=src_addr, dst_ip=ip)
        tcp1 = TCP(1235, dest_port)
        tcp1.flags["FYN"] = 1
        place_holder = 0
        temp_header = pack('!4s4sBBH', bytes(map(int, ip1.src_ip.split('.'))), bytes(map(int, ip1.dst_ip.split('.'))),
                           place_holder, ip1.protocol, 20)
        temp_header = temp_header + tcp1.header_packer()
        tcp_checksum = tcp1.calculate_checksum(temp_header)
        print(f"{temp_header} -> {tcp_checksum}")
        concat_flags = (tcp1.flags["CWR"] << 7) + (tcp1.flags["ECE"] << 6) + (tcp1.flags["URG"] << 5) + \
                       (tcp1.flags["ACK"] << 4) + (tcp1.flags["PSH"] << 3) + (tcp1.flags["RST"] << 2) + \
                       (tcp1.flags["SYN"] << 1) + (tcp1.flags["FYN"])
        offset = 5 << 4
        tcp_header = pack('!HHLLBBHHH', tcp1.src_port, tcp1.dst_port, tcp1.seq_num, tcp1.ack_num, offset,
                          concat_flags, tcp1.window_size, tcp_checksum, tcp1.urg)
        datagram = ip1.header_packer() + tcp_header
        sock.sendto(datagram, (ip, 0))
        time.sleep(delay)


def fyn_scan(ip, start_port, end_port, delay=4):
    start_time = int(time.time())
    recv_thread = Thread(target=recv_fyn_scan, args=(ip, end_port - start_port + 1, delay))
    recv_thread.start()
    queue = []
    for i in range(start_port, end_port + 1):
        queue.append(i)
    q = [[] for _ in range(6)]
    while len(queue) > 0:
        for i in range(0, 6):
            if len(queue) > 0:
                q[i].append(queue.pop())
            else:
                break
    send_threads = []
    for i in range(0, 6):
        temp = Thread(target=send_fyn_scan, args=(ip, q[i], delay))
        send_threads.append(temp)
        temp.start()
    for i in send_threads:
        i.join()
    recv_thread.join()
    fyn_list.sort()
    temp_set = set(fyn_list)
    for i in temp_set:
        print(f"port {i} is closed")


windows_dict = {}


def recv_windows_scan(ip, length, delay):
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ip1 = Ipv4()
    tcp1 = TCP()
    start_time = int(time.time())
    while True:
        if int(delay * length) < int(time.time()) - start_time:
            break
        data, addr = connection.recvfrom(65535)
        ipv4_header = ip1.parser(data[14:])
        if (ipv4_header[10] == ip) & (ipv4_header[11] == src_addr):
            if ipv4_header[8] == socket.IPPROTO_TCP:
                tcp_header = tcp1.parser(ip1.data)
                if tcp_header[6]["RST"] == 1 and tcp_header[-3] != 0:
                    if windows_dict.get(tcp1.src_port) is None:
                        windows_dict[tcp1.src_port] = 'open'
                if tcp_header[6]["RST"] == 1 and tcp_header[-3] == 0:
                    if windows_dict.get(tcp1.src_port) is None:
                        windows_dict[tcp1.src_port] = 'closed'


def send_windows_scan(ip, ports, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while len(ports) > 0:
        dest_port = ports.pop()
        ip1 = Ipv4(src_ip=src_addr, dst_ip=ip)
        tcp1 = TCP(1234, dest_port)
        tcp1.flags["ACK"] = 1
        place_holder = 0
        temp_header = pack('!4s4sBBH', bytes(map(int, ip1.src_ip.split('.'))), bytes(map(int, ip1.dst_ip.split('.'))),
                           place_holder, ip1.protocol, 20)
        temp_header = temp_header + tcp1.header_packer()
        tcp_checksum = tcp1.calculate_checksum(temp_header)
        print(f"{temp_header} -> {tcp_checksum}")
        concat_flags = (tcp1.flags["CWR"] << 7) + (tcp1.flags["ECE"] << 6) + (tcp1.flags["URG"] << 5) + \
                       (tcp1.flags["ACK"] << 4) + (tcp1.flags["PSH"] << 3) + (tcp1.flags["RST"] << 2) + \
                       (tcp1.flags["SYN"] << 1) + (tcp1.flags["FYN"])
        offset = 5 << 4
        tcp_header = pack('!HHLLBBHHH', tcp1.src_port, tcp1.dst_port, tcp1.seq_num, tcp1.ack_num, offset,
                          concat_flags, tcp1.window_size, tcp_checksum, tcp1.urg)
        datagram = ip1.header_packer() + tcp_header
        sock.sendto(datagram, (ip, 0))
        time.sleep(delay)


def windows_scan(ip, start_port, end_port, delay):
    recv_thread = Thread(target=recv_windows_scan, args=(ip, end_port - start_port + 1, delay))
    recv_thread.start()
    queue = []
    for i in range(start_port, end_port + 1):
        queue.append(i)
    q = [[] for _ in range(6)]
    while len(queue) > 0:
        for i in range(0, 6):
            if len(queue) > 0:
                q[i].append(queue.pop())
            else:
                break
    send_threads = []
    for i in range(0, 6):
        temp = Thread(target=send_windows_scan, args=(ip, q[i], delay))
        send_threads.append(temp)
        temp.start()
    for i in send_threads:
        i.join()
    recv_thread.join()
    for i in range(start_port, end_port + 1):
        if windows_dict.get(i) is not None:
            print(f"port {i} is {windows_dict[i]}")
        else:
            print(f"port {i} is filtered")


def main(argv):
    ip_fqdn = 0
    start_port = 0
    end_port = 0
    search_type = 0
    delay = 0
    try:
        print(sys.argv)
    except getopt.GetoptError:
        print('main.py -t <ip address or FQDN> -p <begin range-end range> -s <type of search> -d <delay>')
        sys.exit(2)
    for i in range(len(sys.argv)):
        if sys.argv[i] == '-h':
            print('main.py -t <ip address or FQDN> -p <begin range-end range> -s <type of search> -d <delay>')
            sys.exit()
        elif sys.argv[i] == '-t':
            ip_fqdn = sys.argv[i+1]
        elif sys.argv[i] == '-p':
            start_port, end_port = sys.argv[i+1].split('-')
            start_port = int(start_port.encode("utf-8"))
            end_port = int(end_port.encode("utf-8"))
        elif sys.argv[i] == '-s':
            search_type = sys.argv[i+1]
        elif sys.argv[i] == '-d':
            delay = sys.argv[i+1]
            delay = int(delay.encode("utf-8"))
    if search_type == 'CS':
        connect_scan(ip_fqdn, start_port, end_port, delay)
    elif search_type == 'AckS':
        ack_scan(ip_fqdn, start_port, end_port, delay)
    elif search_type == 'SynS':
        syn_scan(ip_fqdn, start_port, end_port, delay)
    elif search_type == 'FynS':
        fyn_scan(ip_fqdn, start_port, end_port, delay)
    elif search_type == 'WinS':
        windows_scan(ip_fqdn, start_port, end_port, delay)


if __name__ == "__main__":
    main(sys.argv[1:])

#!/usr/bin/env python3
# Coded By : A_Asaker

import socket
import struct
import binascii
import os

raw_sock=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))

def eth_header(data):
	eth_header=data[:14]
	eth_header_lst=struct.unpack("!6s6sH", eth_header)
	dst_mac = binascii.hexlify(eth_header_lst[0]).decode()
	src_mac = binascii.hexlify(eth_header_lst[1]).decode()
	proto   = eth_header_lst[2]

	print("|+========================# ETHERNET HEADER #========================+|")
	print("|\t [*] Destination Mac : {}:{}:{}:{}:{}:{}".format(dst_mac[:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:]))
	print("|\t [*] Source Mac      : {}:{}:{}:{}:{}:{}".format(src_mac[:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:]))
	data=data[14:]
	return data,proto

def ip_header(data)	:
	ip_header=data[:20]
	ip_header_lst=struct.unpack("!6H4s4s", ip_header)
	ver      = ip_header_lst[0]>>12
	IHL      = (ip_header_lst[0]>>8)&0x0f
	Tos      = ip_header_lst[0]&0x00ff
	Len      = ip_header_lst[1]
	Id       = ip_header_lst[2]
	flags    = ip_header_lst[3]>>13
	off      = ip_header_lst[3]& 0x1fff
	ttl      = ip_header_lst[4]>>8
	ip_proto = ip_header_lst[4]&0x00ff
	chk_sum  = ip_header_lst[5]
	src_ip   = socket.inet_ntoa(ip_header_lst[6])
	dst_ip   = socket.inet_ntoa(ip_header_lst[7])

	print("|+===========================# IP HEADER #===========================+|")
	print("|\t [*] Version           : {}".format(ver))
	print("|\t [*] IHL               : {}".format(IHL))
	print("|\t [*] Type Of Service   : {}".format(Tos))
	print("|\t [*] Total Length      : {}".format(Len))
	print("|\t [*] Identification    : {}".format(Id))
	print("|\t [*] Flags             : {}".format(flags))
	print("|\t [*] Fragment Offset   : {}".format(off))
	print("|\t [*] Time to Live(ttl) : {}".format(ttl))
	print("|\t [*] Protocol          : {}".format(ip_proto))
	print("|\t [*] Header Checksum   : {}".format(chk_sum))
	print("|\t [*] Source IP         : {}".format(src_ip))
	print("|\t [*] Destination IP    : {}".format(dst_ip))

	data=data[20:]
	return data,ip_proto

def tcp_header(data):
	tcp_header=data[:20]
	tcp_header_lst=struct.unpack("!2H2I4H", tcp_header)
	src_port = tcp_header_lst[0]
	dst_port = tcp_header_lst[1]
	seq_num  = tcp_header_lst[2]
	ack_num  = tcp_header_lst[3]
	off      = tcp_header_lst[4]>>12
	res      = (tcp_header_lst[4]>>6)&0x003f
	urg      = int(bool(tcp_header_lst[4]&0x0020))
	ack      = int(bool(tcp_header_lst[4]&0x0010))
	psh      = int(bool(tcp_header_lst[4]&0x0008))
	rst      = int(bool(tcp_header_lst[4]&0x0004))
	syn      = int(bool(tcp_header_lst[4]&0x0002))
	fin      = int(bool(tcp_header_lst[4]&0x0001))
	windo    = tcp_header_lst[5]
	chk_sum  = tcp_header_lst[6]
	urg_pntr = tcp_header_lst[7]

	print("|+==========================# TCP HEADER #===========================+|")
	print("|\t [*] Source Port        : {}".format(src_port))
	print("|\t [*] Destination Port   : {}".format(dst_port))
	print("|\t [*] Sequnce Number     : {}".format(seq_num))
	print("|\t [*] Acknowledge Number : {}".format(ack_num))
	print("|\t [*] Data Offset        : {}".format(off))
	print("|\t [*] Reserved           : {}".format(res))
	print("|\t [*] Flags : ")
	print("|\t\t -URG : {} \t -ACK : {} \t -PSH : {}".format(urg,ack,psh))
	print("|\t\t -RST : {} \t -SYN : {} \t -FIN : {}".format(rst,syn,fin))
	print("|\t [*] Window             : {}".format(windo))
	print("|\t [*] Checksum           : {}".format(chk_sum))
	print("|\t [*] Urgent Pointer     : {}".format(urg_pntr))



	data=data[20:]
	return data

def udp_header(data):
	udp_header=data[:8]
	udp_header_lst=struct.unpack("!4H",udp_header)
	src_port = udp_header_lst[0]
	dst_port = udp_header_lst[1]
	Len      = udp_header_lst[2]
	chk_sum  = udp_header_lst[3]
	
	print("|+==========================# UDP HEADER #===========================+|")
	print("|\t [*] Source Port      : {}".format(src_port))
	print("|\t [*] Destination Port : {}".format(dst_port))
	print("|\t [*] Length           : {}".format(Len))
	print("|\t [*] Checksum         : {}".format(chk_sum))

	data=data[8:]
	return data

def main():
	recv_data=raw_sock.recv(2048)
	os.system("clear")
	data, proto=eth_header(recv_data)
	if proto==0x0800:
		data,next_proto=ip_header(data)
	else:
		return
	if next_proto==6:
		data=tcp_header(data)
	elif next_proto==17:
		data=udp_header(data)
	else:
		return
	# print(binascii.hexlify(data).decode())

if __name__ == '__main__':
	while 1:
		main()

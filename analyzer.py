import socket
import struct


# For UDP: Get Source and Destination Ports , Data ...
def unpack_udp(data):
    src_port , dest_port , length , checksum = struct.unpack('! H H H H',data[:8])
    return  src_port , dest_port , length , data[8:] 


# for TCP : Get Source and Destination ports , TCP Flags ...
def unpack_tcp(data):
    src_port , dest_port , seq_num , ack_num , offset_reserved , flags , windows , checksum , urg_pointer = struct.unpack('! H H L L B B H H H',data[:20])
    offset = offset_reserved >> 4 
    reserved = offset_reserved & 15
    cwr = (flags >> 7) & 1
    ece = (flags >> 6) & 1
    urg = (flags >> 5) & 1
    ack = (flags >> 4) & 1
    psh = (flags >> 3) & 1
    rst = (flags >> 2) & 1
    syn = (flags >> 1) & 1
    fin = flags & 1
    return  src_port , dest_port , seq_num ,cwr , ece, urg ,ack ,psh, rst, syn ,fin , data[20:]


# Get Source and Destination IP , Flags , Payload ...
def unpack_ip(data):
    version_header_length , tos , total_length , identification , flags_n_offset , ttl, p , header_checksum , src_ip , dest_ip = struct.unpack('! B B H H H B B H 4s 4s',data[:20]) 
    version = version_header_length >> 4
    header_length = version_header_length & 15
    xff = (flags_n_offset >> 15) 
    dff = (flags_n_offset >> 14) 
    mff = (flags_n_offset >> 13) 
    return p,total_length,ttl ,get_ip(src_ip) ,get_ip(dest_ip) ,xff ,dff ,mff ,data[20:]


   
# Get Source and Destination MAC and Protocol
def unpack_frame(data):
    dest , src , p = struct.unpack('!6s6sH',data[:14])
    return get_mac(dest),get_mac(src),socket.htons(p),data[14:]


# Converts bytes to formatted MAC Address
def get_mac(byte_addr):
    formatted = map('{:02x}'.format, byte_addr)
    return ':'.join(formatted).upper()


# Converts bytes to formatted IP Address
def get_ip(ip):
    return '.'.join(map(str, ip))




# Enter Main loop
def main():
    s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac,src_mac,protocol,data = unpack_frame(raw_data)
        p, total_length,ttl ,src_ip ,dest_ip,xff ,dff ,mff , payload = unpack_ip(data)

        print('[*] Destination MAC: {} || Source MAC: {} || Protocol: {}'.format(dest_mac,src_mac,protocol))
        print('[*] Destination IP: {} || Source IP: {} ||Protocol: {}  || TTL: {} || Total Length: {} || Flags: {}.{}.{}'.format(dest_ip,src_ip,p ,ttl,total_length,xff , dff,mff))
        if p == 6:
            src_port , dest_port , seq_num ,cwr , ece, urg ,ack ,psh, rst, syn ,fin  , payload = unpack_tcp(data)
            print('[*] Protocol: TCP || Source Port: {} || Destination Port: {} || Flags: {}.{}.{}.{}.{}.{}.{}.{} || Sequence number: {}'.format(src_port, dest_port, cwr,ece,urg,ack,psh,rst,syn,fin,seq_num))
            print('[*] Data: \n {}'.format(payload))
            print('___________________________________________________________________________________________________________________')
        elif p == 17:
            src_port , dest_port , length , udp_payload = unpack_udp(data)
            print('[*] Protocol: UDP || Source Port: {} || Destination Port: {}'.format(src_port,dest_port))
            print('[*] Data: \n {}'.format(udp_payload))
            print('___________________________________________________________________________________________________________________')


main()

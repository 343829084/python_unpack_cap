#coding=utf8
import struct
import os
import re, collections, dpkt, zlib, sys, time
import pandas as pd #draw picture lib
reload(sys)
sys.setdefaulttencoding('utf8')


#定义消息的大小
MSG_HEADER_FMT="!LL"
MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FMT)
MSG_TRAILER_SIZE = 4

TIME_ZOME = "Asia/Shanghai"

def pcap_packet_generator(pcap_file):
    with open(pcap_file, 'rb') as f:
        cap = dpkt.pcap.Reader(f)

        remains = ""
        sport = 0
        dport = 0
        for ts, payload in cap:
            if not len(payload)>0:
                continue

            eth = dpkt.ethernet.Ethernet(payload)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
        
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                data = tcp.data

                if not len(data) > 0:
                    continue

                sport = tcp.sport
                dport = tcp.dport
            else:
                udp = ip.data
                data = udp.data

                if not len(data) > 0:
                    continue

                sport = udp.sport
                dport = udp.dport


            packet_time = pd.to_datetime(ts*1000000000).tz_localize('UTC').tz_convert(TIME_ZOME)
            yield packet_time, (ip.src, sport, ip.dst, dport), data, len(data)

def pcap_generator(pcap_file):
    remains = collections.defaultdict(str)
    counter = 0
    for packet_time, peers, data, data_len in pcap_packet_generator(pcap_file):
        remain = remains[peers]

        if len(remain) > 0:
            data = remain + data
            remains[peers] = str()

        pos = 0
        while True:
            if pos + MSG_HEADER_SIZE > len(data):
                break

            packet_no, body_len = struct.unpack(MSG_HEADER_FMT, data[pos:pos+MSG_HEADER_SIZE])
            if pos+MSG_HEADER_SIZE+body_len+MSG_TRAILER_SIZE > len(data):
                break

            yield packet_time, packet_no, data[pos+MSG_HEADER_SIZE : pos+MSG_HEADER_SIZE+body_len]
            pos += MSG_HEADER_SIZE + body_len + MSG_TRAILER_SIZE

        if pos < len(data):
            peers = list(peers)
            peers[4] = peers[4] + data_len
            peers = tuple(peers)
            remains[peers] = data[pos:]


if __name__ == "__main__":
    load_pcap = pcap_generator
    for packet_time, packet_no, body in load_pcap("file.cap"):
        if len(body) == 0:
            continue

        #根据你的消息结构进行，从body中将消息的各部分解出来
        print packet_no, packet_time

# AMT's Traffic Analysis Only. 
# Royson Lee - 25 Jun 2017
#! /usr/bin/env python2.7

from scapy.all import *
try:
    from scapy.layers.ssl_tls import *
except ImportError:
    from scapy_ssl_tls.ssl_tls import *
from netfilterqueue import NetfilterQueue
import sys
import struct
import ssl
import time

datasize = {}
last_timing = {}
timing = {}
REVERSE_HTTPS_PACKET_THRESHOLD = 90
REVERSE_TCP_PACKET_THRESHOLD = 78

REVERSE_HTTPS_SIZE_UBOUND = 2700000
REVERSE_HTTPS_SIZE_LBOUND = 1200000
REVERSE_HTTPS_TIME_UBOUND = 0.1
REVERSE_HTTPS_TIME_LBOUND = 0.001

REVERSE_TCP_SIZE_UBOUND = 2700000
REVERSE_TCP_SIZE_LBOUND = 1000000
REVERSE_TCP_TIME_UBOUND = 0.3
REVERSE_TCP_TIME_LBOUND = 0.01

# For Evaluation
pktdump = PcapWriter("test.pcap",append=True, sync=True)

def check_meterpreter_https_signature(sizes, timings):    
    # Check if sizes start with 256 contains 16448 and contains
    # 176 after
    try:
        if 256 in sizes[0:3] \
        and sizes.index(16448) < (len(sizes) - sizes[::-1].index(176) - 1):
            return \
            REVERSE_HTTPS_SIZE_LBOUND < total_bytes(sizes, 16448, 176) < REVERSE_HTTPS_SIZE_UBOUND \
            and \
            REVERSE_HTTPS_TIME_LBOUND < mean_timing(timings) < REVERSE_HTTPS_TIME_UBOUND
    except (ValueError, IndexError) as e:
        return False
            
    return False

def check_meterpreter_tcp_signature(sizes, timings):
    try:
        if 144 in sizes[0:3] \
        and sizes.index(16448) < (len(sizes) - sizes[::-1].index(144) - 1):
            return \
            REVERSE_TCP_SIZE_LBOUND < total_bytes(sizes, 16448, 144) < REVERSE_TCP_SIZE_UBOUND \
            and \
            REVERSE_TCP_TIME_LBOUND < mean_timing(timings) < REVERSE_TCP_TIME_UBOUND
    except (ValueError, IndexError) as e:
        return False
    return False

def total_bytes(sizes, first, second):
    # This function counts the total number of bytes between
    # and excluding first and second
    # Assume first and second exist and 
    # sizes.index(second) > sizes.index(first)
    try:
        f_i = sizes.index(first)
        s_i = sizes[f_i:].index(second)
        print(sum(sizes[f_i+1:f_i+s_i]))
        return sum(sizes[f_i+1:f_i+s_i])
    except (ValueError, IndexError) as e:
        return 0

def signature_after(sizes, first, signature):
    # This function checks if a signature exist after sizes.index(first)
    try:
        f_i = sizes.index(first)
        s_i = sizes[f_i:].index(signature[0])
        return sizes[f_i+s_i:][0:len(signature)] == signature
    except (ValueError, IndexError) as e:
        return False

def mean_timing(timings):
    print((sum(timings)/len(timings)))
    return(sum(timings)/len(timings))

def retrieve_key(pkt):
    key = str(pkt.src) + str(pkt[TCP].sport) +\
          str(pkt.dst) + str(pkt[TCP].dport)
    return key

def alert(pkt, msg):
    print("[*] Possible " + msg + " Detected")
    print("[*] Source: " + str(pkt.src) + ":" + str(pkt[TCP].sport))
    print("[*] Destination: " + str(pkt.dst) + ":" + str(pkt[TCP].dport))


def analyse_pkt(data):
    pkt = IP(data.get_payload())
    
    if pkt.haslayer('SSL') and pkt.haslayer('TLSServerHello'):
        #Wipe information
        key = retrieve_key(pkt)
        last_timing[key] = None
        timing[key] = []
        datasize[key] = [] 
    if pkt.haslayer('SSL') and not pkt.haslayer('TLSHandshake') \
    and not pkt.haslayer('TLSChangeCipherSpec'):
        records = pkt[SSL].records

        key = retrieve_key(pkt)
        new_datasize = 0
        for r in records:
            if r.haslayer('TLSRecord'):
                new_datasize = new_datasize + r[TLSRecord].length
        if new_datasize:
            #Get timing of key
            curr_time = time.time()
            if not last_timing.setdefault(key, None): 
                timing.setdefault(key,[]).append(0)
            else:
                prev_time = last_timing[key]
                timing[key].append(curr_time - prev_time)
            last_timing[key] = curr_time
            datasize.setdefault(key, []).append(new_datasize) 
            
            pktdump.write(pkt)
            # print(key + " : " +  str(len(timing[key])))
            # Extracting up to threshold and then evaluate
            if len(timing[key]) == REVERSE_TCP_PACKET_THRESHOLD:
                #print(timing[key])
                #print(datasize[key])
                if check_meterpreter_tcp_signature(datasize[key],timing[key]):
                    alert(pkt, "reverse_tcp Meterpreter Session")
            if len(timing[key]) == REVERSE_HTTPS_PACKET_THRESHOLD:
                #print(timing[key])
                #print(datasize[key])
                if check_meterpreter_https_signature(datasize[key],timing[key]): 
                    alert(pkt, "reverse_https Meterpreter Session")
    data.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, analyse_pkt)  # 1 is the queue number
try:
    print("Awaiting data")
    nfqueue.run()
except KeyboardInterrupt:
    pass


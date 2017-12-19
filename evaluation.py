#! /usr/bin/env python2.7
# Royson Lee - 25 Jun 2017
# This file is used to evaluate the false positivities based on pcap files
# Assumes there are no meterpreter traffic as input

from scapy.all import *
try:
    from scapy.layers.ssl_tls import *
except ImportError:
    from scapy_ssl_tls.ssl_tls import *
import os
import sys
import struct
import ssl

datasize = {}
last_timing = {}
timing = {}
REVERSE_HTTPS_PACKET_THRESHOLD = 89
REVERSE_TCP_PACKET_THRESHOLD = 78

REVERSE_HTTPS_SIZE_UBOUND = 2700000
REVERSE_HTTPS_SIZE_LBOUND = 1500000
REVERSE_HTTPS_TIME_UBOUND = 0.1
REVERSE_HTTPS_TIME_LBOUND = 0.001

REVERSE_TCP_SIZE_UBOUND = 2700000
REVERSE_TCP_SIZE_LBOUND = 1200000
REVERSE_TCP_TIME_UBOUND = 0.3
REVERSE_TCP_TIME_LBOUND = 0.01

TOTAL_IDENTIFIED_TRAFFIC = 0
TOTAL_FP_WINDOWS_TCP = 0
TOTAL_FP_WINDOWS_HTTPS = 0

IDENTIFIED_TRAFFIC = 0
FALSE_POSITIVE_WINDOWS_TCP = 0
FALSE_POSITIVE_WINDOWS_HTTPS = 0

def clear_buffer():
    global IDENTIFIED_TRAFFIC
    IDENTIFIED_TRAFFIC = 0
    global FALSE_POSITIVE_WINDOWS_TCP
    FALSE_POSITIVE_WINDOWS_TCP = 0
    global FALSE_POSITIVE_WINDOWS_HTTPS
    FALSE_POSITIVE_WINDOWS_HTTPS = 0 

def false_positive_rate():
    if IDENTIFIED_TRAFFIC > 0:
        return (FALSE_POSITIVE_WINDOWS_TCP + FALSE_POSITIVE_WINDOWS_HTTPS)/IDENTIFIED_TRAFFIC*100
    return 0

def total_false_positive_rate():
    if TOTAL_IDENTIFIED_TRAFFIC > 0:
        return (TOTAL_FP_WINDOWS_TCP + TOTAL_FP_WINDOWS_HTTPS)/TOTAL_IDENTIFIED_TRAFFIC*100
    return 0

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
    key = str(pkt[IP].src) + str(pkt[TCP].sport) +\
          str(pkt[IP].dst) + str(pkt[TCP].dport)
    return key

def alert(pkt, msg):
    print("[*] Possible " + msg + " Detected")
    print("[*] Source: " + str(pkt[IP].src) + ":" + str(pkt[TCP].sport))
    print("[*] Destination: " + str(pkt[IP].dst) + ":" + str(pkt[TCP].dport))


def analyse_pkt(pkt):
    if pkt.haslayer('TLSServerHello'):
        #Wipe information
        key = retrieve_key(pkt)
        last_timing[key] = None
        timing[key] = []
        datasize[key] = [] 
    if not pkt.haslayer('TLSHandshake') \
    and not pkt.haslayer('TLSChangeCipherSpec'):
        records = pkt[SSL].records

        key = retrieve_key(pkt)
        new_datasize = 0
        for r in records:
            if r.haslayer('TLSRecord'):
                new_datasize = new_datasize + r[TLSRecord].length
        if new_datasize:
            #Get timing of key
            curr_time = pkt.time
            if not last_timing.setdefault(key, None): 
                timing.setdefault(key,[]).append(0)
            else:
                prev_time = last_timing[key]
                timing[key].append(curr_time - prev_time)
            last_timing[key] = curr_time
            datasize.setdefault(key, []).append(new_datasize) 

            # Extracting up to threshold and then evaluate
            if len(timing[key]) == REVERSE_TCP_PACKET_THRESHOLD:
                global IDENTIFIED_TRAFFIC
                global TOTAL_IDENTIFIED_TRAFFIC
                IDENTIFIED_TRAFFIC = IDENTIFIED_TRAFFIC + 1
                TOTAL_IDENTIFIED_TRAFFIC = TOTAL_IDENTIFIED_TRAFFIC + 1
                if check_meterpreter_tcp_signature(datasize[key],timing[key]):
                    alert(pkt, "reverse_tcp Meterpreter Session")
                    global FALSE_POSITIVE_WINDOWS_TCP
                    global TOTAL_FP_WINDOWS_TCP
                    FALSE_POSITIVE_WINDOWS_TCP = FALSE_POSITIVE_WINDOWS_TCP + 1
                    TOTAL_FP_WINDOWS_TCP = TOTAL_FP_WINDOWS_TCP + 1
            if len(timing[key]) == REVERSE_HTTPS_PACKET_THRESHOLD:
                if check_meterpreter_https_signature(datasize[key],timing[key]): 
                    alert(pkt, "reverse_https Meterpreter Session")
                    global FALSE_POSITIVE_WINDOWS_HTTPS
                    global TOTAL_FP_WINDOWS_HTTPS
                    FALSE_POSITIVE_WINDOWS_HTTPS = FALSE_POSITIVE_WINDOWS_HTTPS + 1
                    TOTAL_FP_WINDOWS_HTTPS = TOTAL_FP_WINDOWS_HTTPS + 1

path = "./pcaps"

if len(sys.argv) > 1:
    path = "."
    files = sys.argv[1:]
else:
    files = os.listdir(path)
for f in files:
    print("Opening.. " + path + "/" + f)
    with PcapReader(path + "/" + f) as pr:
        for p in pr:
            if IP in p and TCP in p and SSL in p:
                analyse_pkt(p)
    print(f)
    print("---------------------")
    print("[*] Total SSL connections that hit Threshold: " + str(IDENTIFIED_TRAFFIC))
    print("[*] Total False reverse_tcp: " + str(FALSE_POSITIVE_WINDOWS_TCP))
    print("[*] Total False reverse_https: " + str(FALSE_POSITIVE_WINDOWS_HTTPS))
    print("[*] False Positive: " + str(false_positive_rate()) + "%")
    clear_buffer()
print("Total")
print("---------------------")
print("[*] Total SSL connections that hit Threshold: " + str(TOTAL_IDENTIFIED_TRAFFIC))
print("[*] Total False reverse_tcp: " + str(TOTAL_FP_WINDOWS_TCP))
print("[*] Total False reverse_https: " + str(TOTAL_FP_WINDOWS_HTTPS))
print("[*] False Positive: " + str(total_false_positive_rate()) + "%")


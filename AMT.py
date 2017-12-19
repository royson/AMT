# AMT Without Traffic Analysis
# Royson Lee - 25 Jun 2017
#! /usr/bin/env python2.7
from scapy.all import *
try:
    from scapy.layers.ssl_tls import *
except ImportError:
    from scapy_ssl_tls.ssl_tls import *
from netfilterqueue import NetfilterQueue
import sys
import binascii
import struct
import httplib
import ssl

# Outgoing interface for packet replay
INTERFACE = "enp0s8"

# Meterpreter HTTP response signature
HEADER = 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
HEADER += 'Connection: Keep-Alive\r\nServer: Apache\r\nContent-Length:'

# Meterpreter HTTPS response signature
HTTPS_CONTENT = '<html><body><h1>It works!</h1></body></html>'
HTTPS_ERROR_CONTENT = '<html><head><title>404 Not Found</title></head><body><h1>Not found'
HTTPS_ERROR_CONTENT += '</h1>The requested URL / was not found on this server.'
HTTPS_ERROR_CONTENT += '<p><hr></body></html>'


def xor_bytes(key, data):
    if sys.version_info[0] < 3:
        dexored = ''.join(chr(ord(data[i]) ^ key[i % len(key)])
                          for i in range(len(data)))
    else:
        dexored = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return dexored


def decode_meterpreter_pkt(opl, xor_key, pkt):
    pl = opl[12:]
    try:
        body = xor_bytes(xor_key, pl[:40])
        filter_pkt = body[8:15].decode("utf-8")
    except UnicodeDecodeError:
        return opl

    # Only decode the entire packet if it starts with stdapi_ or core_
    if filter_pkt == "stdapi_" or filter_pkt[:5] == "core_":
        try:
            body = xor_bytes(xor_key, pl)
            command = body[8:50].decode("utf-8").split(')')
            print("[*] Meterpreter Command: " + command[0] + " Detected")
        except:
            print("[*] Packet too small. Unknown Command Detected.")
        print("[*] Attacker IP: " + str(pkt.src) + ":" + str(pkt[TCP].sport) 
             + ". Affected host: " + str(pkt.dst) + ":" + str(pkt[TCP].dport))

        #[Optional] Replay the unencoded packet for IDS detection.
        replay_pkt(body, pkt.src, pkt.dst)
        return body
    return opl


def replay_pkt(data, source, dest):
    p = IP(src=source, dst=dest) / TCP() / ""
    p[Raw].load = data
    send(p, iface=INTERFACE)


def test_meterpreter_reverse_https_default_uri(src, sport):
    # conn = httplib.HTTPSConnection(src, sport)
    # Remove certificate verification
    conn = httplib.HTTPSConnection(
        src, sport, context=ssl._create_unverified_context())
    conn.request("GET", "/")
    r1 = conn.getresponse()
    conn.request("GET", "/apache")
    r2 = conn.getresponse()
    conn.request("GET", "/")
    r3 = conn.getresponse()
    conn.close()

    if r1.status == 200 and r1.reason == "OK" \
            and r2.status == 200 and r2.reason == "OK" \
            and r3.status == 404 and r3.reason == "File not found" \
            and r1.read() == HTTPS_CONTENT \
            and r2.read() == '' \
            and r3.read() == HTTPS_ERROR_CONTENT:
        print("[*] Meterpreter default_uri HTTPS session detected..")
        print("[*] Session stopped.")


def analyse_pkt(data):
    pkt = IP(data.get_payload())

    # Check if packet is part of a TLS Handshake
    if TLSServerHello in pkt:
        test_meterpreter_reverse_https_default_uri(pkt.src, pkt[TCP].sport)
    elif pkt.haslayer('SSL'):
        #Stop execution if packet is encrypted
        return

    payload = pkt[TCP].payload
    if type(payload) is scapy.packet.Raw:
        pl = str(payload)
        # Check if packet has the signature of a Meterpreter's HTTP Response
        if pl.startswith(HEADER):
            http_arr = pl.split('\r\n', 6)

            if len(http_arr) > 4:
                if http_arr[5] != "":
                    pl = http_arr[5]
                elif len(http_arr) > 5 and http_arr[6] != "":
                    pl = http_arr[6]

    # Else, check if payload has Meterpreter's 4 byte XOR encoding
        if len(pl) >= 12:
            xor_key = struct.unpack('BBBB', pl[:4][::-1])

            # Attempt to meterpreter decode
            pl = decode_meterpreter_pkt(pl, xor_key, pkt)
        data.accept()

        #[Extension] Use pl as payload
        
    else:
        data.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, analyse_pkt)  # 1 is the queue number
try:
    print("Awaiting data")
    nfqueue.run()
except KeyboardInterrupt:
    pass


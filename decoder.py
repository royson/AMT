#!/usr/bin/python
# Royson Lee - 25 May 2017
# For individual decoding purposes of meterpreter XOR encoding
# Reference: https://github.com/rapid7/metasploit-payloads/blob/master/python/meterpreter/meterpreter.py

import sys
import binascii
import struct

def xor_bytes(key, data):
    if sys.version_info[0] < 3:
        dexored = ''.join(chr(ord(data[i]) ^ key[i % len(key)])
                          for i in range(len(data)))
    else:
        dexored = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return dexored


if len(sys.argv) != 2:
    print("Input hexademical string to decode")
else:
    hexa = "".join(sys.argv[1].split())

    packet = binascii.a2b_hex(hexa)

    xor_key = struct.unpack('BBBB', packet[:4][::-1])
    
    header = xor_bytes(xor_key, packet[4:12])

    pkt_length, _ = struct.unpack('>II', header)
    body = xor_bytes(xor_key, packet[12:])
    
    if len(packet) - 4 == pkt_length:  # Check encoding scheme
        try:
            filter_pkt = body[8:15].decode("utf-8")
        except UnicodeDecodeError:
            print("Cannot decode hex.")
            sys.exit()
        if filter_pkt == "stdapi_" or filter_pkt[:5] == "core_":
            print("[*] Meterpreter Command Detected")
        else:
            print("[*] 4 XOR Encoding Scheme but further analysis is needed.")
    else:
        print("[*] Not in encoding scheme. Decode anyway.")
    try:
      print("Command: " + body[8:25].decode("utf-8"))
      print("[*] Header:")
      print(header)
      print("[*] Body:")
      print(body)
      print("[*] Hex: " + body.hex())
    except UnicodeDecodeError:
      print("[*] Decoding failed.")


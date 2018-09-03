#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime
from termcolor import colored

if len(sys.argv) !=3 :
    print ("Uso: python escaneo_xmas.py <IP> <lista de puertos separados por comas>")
    exit()

target = sys.argv[1]
port = sys.argv[2]
port.replace(" "," ")
scanPorts = port.strip().split(':')

start_clock = datetime.now()

try:
    ping = sr1(IP(dst = target)/ICMP())
    print("\n [*] Objetivo conectado, comenzando escaner...")
except Exception:
    print (colored("\n [!] No se puede conectar con el objetivo", 'red', attrs=['bold', 'blink']))
    print (" [!] Saliendo...")
    sys.exit(1)

print(" [*] Escaner comenzado: " + strftime("%H:%M:%S") + "!\n")

for i in scanPorts:
    src_port = RandShort()
    response = sr1(IP(dst=target)/TCP(dport=int(i),flags="FPU"),timeout=10)
    if (str(type(response))=="<class 'NoneType'>"):
        print(colored("\n Puerto " + str(port) + ": Abierto|Filtrado", 'green', attrs=['bold', 'blink']))

# If the server responds with the RST flag set inside a TCP packet,
# the port is closed on the server.
    elif(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x14):
            print(colored("\n Puerto " + str(port) + ": Cerrado", 'red', attrs=['bold', 'blink']))

# If the server responds with the ICMP packet with an ICMP unreachable error type 3 and ICMP code 1, 2, 3, 9, 10, or 13,
# then the port is filtered and it cannot be inferred from the response whether the port is open or closed.
    elif(response.haslayer(ICMP)):
        if (response.getlayer(ICMP).type==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print(colored("\n Puerto " + str(port) + ": Filtrado", 'red', attrs=['bold', 'blink']))

stop_clock = datetime.now()
total_time = stop_clock - start_clock
print("\n [*] ¡Escaneo finalizado!")
print(" [*] Duración total: " + str(total_time))

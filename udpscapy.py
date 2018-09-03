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
    print (colored(" Uso: python escaneo_tcp.py <IP> <lista de puertos separados por comas>", 'magenta', attrs=['bold', 'blink']))
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
    conf.verb = 0
    response = sr1(IP(dst=target)/UDP(dport=int(i)))

    # If the server sends no response to the client’s UDP request packet for that port,
    # it can be concluded that the port on the server is either open or filtered. No final state of the port can be decided.
    if (str(type(response))=="<class 'NoneType'>"):
        print(colored("\n Puerto " + str(port) + ": Abierto|Filtrado", 'green', attrs=['bold', 'blink']))

    # The client sends a UDP packet with the port number to connect to.
    # If the server responds to the client with a UDP packet, then that particular port is open on the server.
    elif (response.haslayer(UDP)):
        print(colored("\n Puerto " + str(port) + ": Abierto", 'green', attrs=['bold', 'blink']))

    # The client sends a UDP packet and the port number it wants to connect to, but the server responds with an ICMP
    # port unreachable error type 3 and code 3, meaning that the port is closed on the server.
    elif(response.haslayer(ICMP)):
        if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code)==3):
            print(colored("\n Puerto " + str(port) + ": Cerrado", 'red', attrs=['bold', 'blink']))

        # If ICMP error type 3 and code 1, 2, 9, 10, or 13, then that port on the server is filtered.
    elif(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]):
            print(colored("\n Puerto " + str(port) + ": Filtrado", 'red', attrs=['bold', 'blink']))

stop_clock = datetime.now()
total_time = stop_clock - start_clock
print("\n [*] ¡Escaneo finalizado!")
print(" [*] Duración total: " + str(total_time))

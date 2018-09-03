#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE VULNERABILIDADES

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO ACK
"""""""""""""""""""""""""""""""""""""""""""""""""""

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
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
port.replace(" ", " ")
scanPorts = port.strip().split(':')

#ports = range(int(min_port), int(max_port)+1)
start_clock = datetime.now() # Start clock for scan time

print("\n")
print ("[*] Escaneo comenzado: " + strftime("%H:%M:%S") + "!\n")

try:
    ping = sr1(IP(dst = target)/ICMP()) # Ping the target
    print ("\n [*] Objetivo conectado, comenzando escaner...")
except Exception: # If ping fail
    print (colored("\n [!] No se puede conectar con el objetivo", 'red', attrs=['bold', 'blink']))
    print (" [!] Saliendo...")
    sys.exit(1)

for i in scanPorts:
    srcport = RandShort()
    conf.verb = 0
    response = sr1(IP(dst=target)/TCP(dport=int(i),flags="A"), timeout =10)
    print ("Respuesta del tipo: " + str(type(response)))

    if (str(type(response))=="<class 'NoneType'>"):
        print (colored("\n [*] Encontrado firewall en el puerto " + str(i), 'red', attrs=['bold', 'blink']))

    elif (response.haslayer(TCP)):
        if (response.getlayer(TCP).flags==0x4):
            print(colored("\n [*] No encontrado firewall " + str(i), 'green', attrs=['bold', 'blink']))

    elif (response.haslayer(ICMP)):
        if (response.getlayer(ICMP).type==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print (colored("\n [*] Encontrado firewall " + int(i), 'red', attrs=['bold', 'blink']))

 # Confirm scan start

stop_clock = datetime.now() # Stop clock for scan time
total_time = stop_clock - start_clock # Calculate scan time
print ("\n [*] ¡Escaneo finalizado!")
print (" [*] Duración total: " + str(total_time))

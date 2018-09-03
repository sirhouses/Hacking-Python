#! /usr/bin/env python
# -*- coding: utf-8 -*-


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
port.replace(" "," ")
scanPorts = port.strip().split(':')

start_clock = datetime.now() # Start clock for scan time
SYNACK = 0x12 # Set flag values for later reference


def checkhost(ip):
        try:
            ping = sr1(IP(dst = ip)/ICMP()) # Ping the target
            print ("\n [*] Objetivo conectado, comenzando escaner...")
        except Exception: # If ping fail
            print (colored("\n [!] No se puede conectar con el objetivo", 'red', attrs=['bold', 'blink']))
            print (" [!] Saliendo...")
            sys.exit(1)

def scanport(port):

        for i in scanPorts:
            srcport = RandShort()
            conf.verb = 0 # Hide output
            SYNACKpkt = sr1(IP(dst = target)/TCP(dport =int(i), flags = "S"), timeout = 10)
            pktflags = SYNACKpkt.getlayer(TCP).flags
            if pktflags == SYNACK:
                return True # If open, return true
            else:
                return False # If closed, return false


checkhost(target)
print (" [*] Escaneo comenzado: " + strftime("%H:%M:%S") + "!\n") # Confirm scan start

#for port in ports:
status = scanport(port)
if status == True:
    print(colored(" Puerto " + str(port) + ": Abierto", 'green', attrs=['bold', 'blink']))
elif status == False:
    print(colored(" Puerto " + str(port) + ": Cerrado", 'red', attrs=['bold', 'blink']))


stop_clock = datetime.now() # Stop clock for scan time
total_time = stop_clock - start_clock # Calculate scan time
print ("\n [*] ¡Escaner finalizado!")
print (" [*] Duración total: " + str(total_time))

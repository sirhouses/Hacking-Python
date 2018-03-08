#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
from modulos.basico import *
from modulos.whois import *
from modulos.smb import *
from modulos.so import *
from termcolor import colored

def menu():
    # Funcion para limpiar pantalla
    os.system('clear')

    print("\n Selecciona una opción \n")
    print("\t1 - Escáner básico")
    print("\t2 - Información Whois")
    print("\t3 - Información SMB")
    print("\t4 - Detectar S.O.")
    print("\t9 - Salir")

while True:

    menu()

    opcionMenu = input("\n Inserta el valor de su opción: ")

    if opcionMenu == "1":
        """Descubrimiento de puertos"""
        print(colored("\n Escáner básico", 'green', attrs=['bold', 'blink']))
        target = input("\n Inserte la IP del objetivo: ")
        basicscans(target)
        input("\n Pulsa una tecla para continuar ")

    elif opcionMenu == "2":
        """Extraer Whois"""
        print(colored("\n Información Whois", 'green', attrs=['bold', 'blink']))
        target = input("\n Inserta un dominio: ")
        whoiscans(target)
        input("\n Pulsa una tecla para continuar")

    elif opcionMenu == "3":
        """Analizar SMB"""
        print(colored("\n Información SMB", 'green', attrs=['bold', 'blink']))
        target = input("\n Inserte la IP del objetivo: ")
        smbscans(target)
        input("\n Pulsa una tecla para continuar")

    elif opcionMenu == "4":
        """Detección de Sistema operativo"""
        print(colored("\n Detectar OS", 'green', attrs=['bold', 'blink']))
        target = input("\n Inserte la IP del objetivo: ")
        soscans(target)
        input("\n Pulsa una tecla para continuar")

    elif opcionMenu == "9":
            """Salir de la aplicación"""
            print(colored("\n See you soon ;)", 'red', attrs=['bold', 'blink']))
            print("\n")
            break
    else:
        print(colored("\n No has pulsado ninguna opción correcta", 'red', attrs=['blink', 'bold']))
        input("\n Pulsa una tecla para continuar")

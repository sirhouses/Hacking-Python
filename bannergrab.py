#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            BANNER GRABBING

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import socket
from optparse import OptionParser
from termcolor import colored


VERSION = "1.0"


def http_banner(ip, port=80, method="HEAD", timeout=60, http_type="HTTP/1.1"):
    #Función para obtener cabecera HTTP
    try:
        assert method in ['GET', 'HEAD']
        assert http_type in ['HTTP/0.9', "HTTP/1.0", 'HTTP/1.1']    #Datos para petición GET
        cr_lf = '\r\n'
        lf_lf = '\n\n'
        crlf_crlf = cr_lf + cr_lf
        res_sep = ''        # Cuanto lee desde el socket del buffer en cada lectura
        rec_chunk = 4096
        print("\n")
        print(" Estableciendo conexión...")
        print("\n")
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        print(" Se ha realizado la conexión con " + ip)
    except:
        print(colored(" No se ha podido conectar con " + ip))

    try:
        req_data = "{} / {}{}".format(method, http_type, cr_lf)  #req_data is como 'HEAD HTTP/1.1 \r\n'
        if http_type == "HTTP/1.1":
            req_data += 'Host: {}:{}{}'.format(ip, port, cr_lf)  #añadiendo cabecera del host a req_data
            req_data += "Connection: close{}".format(cr_lf)
        req_data += cr_lf           #Los encabezados se unen con `\ r \ n` y termina con` \ r \ n \ r \ n
        s.sendall(req_data.encode())
        res_data = b''
        while 1:
            try:
                chunk = s.recv(rec_chunk)
                res_data += chunk
            except socket.error:
                break
            if not chunk:
                break
        if res_data:             #Descodifica res_data tras leer todo el contenido
            res_data = res_data.decode()
        else:
            return '', ''

        if crlf_crlf in res_data:       #Detecta el cuerpo y la cabecera separados
            res_sep = crlf_crlf
        elif lf_lf in res_data:
            res_sep = lf_lf
        if res_sep not in [crlf_crlf, lf_lf] or res_data.startswith('<'):
            return '', res_data
        content = res_data.split(res_sep)       #Separa cabecera y sección de datos de una respuesta u otra
        banner, body = "".join(content[:1]), "".join(content[1:])
        inicio = banner.find("Server:") + 8
        final = banner.find("Last-Modified:")
        banner = banner[inicio:final]

        archivo = open('http_banners.txt','r')
        for bannervulnerable in archivo.readlines():
            if str(bannervulnerable).strip('\n') in str(banner):
                 print(colored("\n Servicio vulnerable: " + str(banner), 'green', attrs=['bold', 'blink']))
                 print(colored("\n Host: " + ip, 'green', attrs=['bold', 'blink']))
            #else:
             #    print(banner)
    except:
        print(colored("\n [-] Imposible recoger información", 'red', attrs=['bold', 'blink']))



def conexion(target,port):
    #Establece conexión con el host objetivo
    try:
        print("\n")
        print(" Estableciendo conexion...")
        print("\n")
        conexion=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        conexion.connect((target, int(port)))
        rec_chunk = conexion.recv(4096)
        print(" Se ha realizado la conexión con " + target + " en el puerto " + port)
    except:
        print(colored(" No se ha podido conectar con " + target + " en el puerto " + port, 'red', attrs=['bold', 'blink']))


    # Busca si el banner del host está en la lista de banners vulnerables
    try:
        archivo = open('other_banners.txt','r')
        for bannervulnerable in archivo.readlines():
            if str(bannervulnerable).strip('\n') in str(rec_chunk):
                print(colored("\n Servicio vulnerable: " + str(rec_chunk), 'green', attrs=['bold', 'blink']))
                print(colored("\n Host: " + target, 'green', attrs=['bold', 'blink']))
            #else:
            #    print(rec_chunk)
    except:
        print(colored("\n [-] Imposible recoger información", 'red', attrs=['bold', 'blink']))
        return


def main():
        parser = OptionParser(usage="%prog [-t target] [-p ports] ",
                  version="thesecuritysentinel.com %prog "+VERSION)
        parser.add_option("-t", "--target", dest="targets",
                          help="Escanea el objetivo en busca de vulnerabilidades", metavar="TARGET")
        parser.add_option("-p", "--ports", dest="ports",
                          help=" Escanea el puerto, servicio y versión. Deben ir separados por comas", metavar="PORTS")

        (options, args) = parser.parse_args()

        if (options.targets == None) | (options.ports == None):
            parser.print_help()
            exit(0)

# Reconoce los puertos introducidos separados por comas

        targets = str(options.targets).split(',')
        ports = str(options.ports).split(',')

        for target in targets:
            for port in ports:
                if port == "80" or port == "443":
                    http_banner(target)

                else:
                    conexion(target, port)


if __name__ == '__main__':
    main()

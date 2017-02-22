#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import socket
import os
import sys
import time
import subprocess
from optparse import OptionParser

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *


DEFAULT_SSL_PORT = 443
DEFAULT_SSL_VERSION = TLSVersion.TLS_1_2

MODE_NORMAL = "NORMAL"
MODE_N_BY_ONE = "N_BY_ONE"


def tls_hello(sock, tls_version):
    client_hello = TLSRecord(version=tls_version) / TLSHandshake() / \
                   TLSClientHello(version=tls_version, compression_methods=range(0xff), cipher_suites=range(0xff))

    sock.sendall(client_hello)

    server_hello = sock.recvall()
#   server_hello.show()


def tls_client_key_exchange(sock, tls_version):
    client_key_exchange = TLSRecord(version=tls_version) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
    client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()

    sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
    sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))

    server_finished = sock.recvall()
#server_finished.show()

def send_nbyte(request_data, send_packet_len, send_byte_len):
    send_data = request_data[send_packet_len:][:send_byte_len]
    sock.sendall(to_raw(TLSPlaintext(data=send_data), sock.tls_ctx))
    return (send_packet_len + send_byte_len)

def send_recv_data(sock, file_name, ip, mode):
    request_data = get_file_data(file_name, ip)

    if not request_data:
        print("Request Data is empty")

    print("*** Send request data to server. ***")

    if mode == MODE_N_BY_ONE:
        data_len = len(request_data)
        sent_packet_len = 0

        while sent_packet_len <= data_len:
            sent_packet_len = send_nbyte(request_data, sent_packet_len, 1)
            time.sleep(0.01)
            sent_packet_len = send_nbyte(request_data, sent_packet_len, 16384)
            time.sleep(0.01)
    else:
        sock.sendall(to_raw(TLSPlaintext(data=request_data), sock.tls_ctx))

    print("*** Recevied response data from server ***")
    resp = sock.recvall()
    resp.show()

def tls_handshake(sock, host, tls_version):
    try:
        tls_hello(sock, tls_version)
        tls_client_key_exchange(sock, tls_version)

        print("Finished handshake.")
#    print(sock.tls_ctx)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        return False

    return True

def connect_socket(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect(host)
        sock = TLSSocket(sock, client=True)
        print("Connected to server: %s" % (host,))
    except socket.timeout:
        print("Failed to open connection to server: %s" % (host,))
        return None

    return sock

def get_file_data(file_name, ip):
    data = ""
    try:
	print ("%s" % file_name)
        f = open(file_name, 'r')
    except:
        print("Unexpected error:", sys.exc_info()[0])
    else:
        for line in f.readlines():
            data += line.encode("utf-8").replace("HOST_IP_DEFINE", str(ip))
    finally:
    	f.close()

    return data

def validate_ssl_version(version):
    ssl_version_map = {
        "TLS_1_0" : TLSVersion.TLS_1_0,
        "TLS_1_1" : TLSVersion.TLS_1_1,
        "TLS_1_2" : TLSVersion.TLS_1_2,
#"SSL_3_0" : TLSVersion.SSL_3_0
    }
    return  ssl_version_map[version]

def sslv3_process(file_name, ip):
    request_data = get_file_data(file_name, ip)

    if not request_data:
        print("Request Data is empty")

    data = request_data.replace('\n', '')
    print("*** Send request data to server. ***")
# curl option 
# -k : 인증 건너 뛰기, -v 서버와의 연결하면서 주고 받은 정보를 표시, -H : request header
# -I : HTTP 헤더 정보를 정보 취득, 
    output = subprocess.check_output(["curl", "-k", "-v",  "-H", data, "--sslv3", ip])
    print("*** Recived data from server. ***")
    print (output)

if __name__ == "__main__":
    parser = OptionParser('Usage: sendpk_ssl.py -i ip_address -p port -s ssl_version -f request_file')
    parser.add_option('-p', '--port', dest='port', type='int', help='port')
    parser.add_option('-i', '--ip', dest='ip', type='string', help='ip')
    parser.add_option('-s', '--ssl', dest='ssl_version', type='string', help='ssl_version: TLS_1_0, TLS_1_1, TLS_1_2, SSL_3_0')
    parser.add_option('-f', '--file', dest='file_name', type="string", help='file name')
    parser.add_option('-m', '--mode', dest='mode', type="string", help='NORMAL, N_BY_ONE')

    (options, args) = parser.parse_args()

    if len(sys.argv) <= 4:
        parser.print_help()
        exit(1)

    if not options.ip or not options.file_name:
        print ('Please input port or ip or file.')
        exit(1)

    if  options.port is None:
        options.port = DEFAULT_SSL_PORT

    if  options.ssl_version is None:
        tls_version = DEFAULT_SSL_VERSION
    elif options.ssl_version == "SSL_3_0":
        sslv3_process(options.file_name, options.ip)
        exit(0)
    else:
        tls_version = validate_ssl_version(options.ssl_version)

    if options.mode == "N_BY_ONE":
        mode = MODE_N_BY_ONE
    else:
        mode = MODE_NORMAL

    server = (options.ip, options.port)
    sock = connect_socket(server)
    if sock and tls_handshake(sock, server, tls_version) is True:
        send_recv_data(sock, options.file_name, options.ip, mode)

    sock.close();

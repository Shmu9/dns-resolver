import sys
import os
import json
import time
from _thread import *
import socket
from datetime import datetime,date,timedelta
from threading import Timer
import re
import DNSmessage

'''
TODO:
- error message/handling for invalid name (if server can't find name)
'''

def parse_cmd_line(argv):
    QTYPES = ('A', 'NS', 'MX', 'CNAME', 'PTR')

    def usage_exit():
        print(f"usage: {sys.argv[0]} <resolver_ip> <resolver_port> <name> [type=A] [timeout=5]\n\
                e.g. {sys.argv[0]} 127.0.0.1 5300 example.com NS 3", file=sys.stderr)
        sys.exit(1)

    if len(argv) < 4 or len(argv) > 6:
        usage_exit()

    if re.match("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", argv[1]) is None:
        usage_exit()
    if re.match("[0-9]{1,5}", argv[2]) is None:
        usage_exit()
    # if int(argv[2]) < 1024 or int(argv[2]) > 65535:
    #     print(f"error: port number must be in the range 1024-65535", file=sys.stderr)
    #     usage_exit()
    if re.match("[a-zA-Z0-9\.\-]+", argv[3]) is None:
        usage_exit()

    resolver_ip = argv[1]
    resolver_port = int(argv[2])
    name = argv[3]
    type = 'A'                      # default
    timeout = 5                     # default

    if len(argv) == 5:
        if argv[4] not in QTYPES and not re.match("[0-9]+", argv[4]):
            usage_exit()
        elif argv[4] in QTYPES:
            type = argv[4]
        elif re.match("[0-9]+", argv[4]):
            timeout = int(argv[4])
    elif len(argv) == 6:
        if (argv[4] in QTYPES and re.match("[0-9]+", argv[5])):
            type = argv[4]
            timeout = int(argv[5])
        elif (argv[5] in QTYPES and re.match("[0-9]+", argv[4])):
            type = argv[5]
            timeout = int(argv[4])
        else:
            usage_exit()
    
    return resolver_ip, resolver_port, name, type, timeout

def request_resolver(resolver_ip, resolver_port, name, type, timeout_delta):
    '''
    Send DNS query to resolver, await response and return it
    '''
    # hostname = socket.gethostname()
    # print(hostname)
    # udpclientip = socket.gethostbyname(hostname)
    # print(udpclientip)

    s = socket.socket(socket.AF_INET,       # IPv4
                      socket.SOCK_DGRAM)    # UDP
    
    addr = (resolver_ip, resolver_port)
    s.settimeout(timeout_delta)
    query = DNSmessage.DNSquery(ID=91, QNAME=name, QTYPE=type)
    msg = query.build_query()
    s.sendto(msg, addr)
    try:
        data, server = s.recvfrom(512)
        response = dns_interpreter.decode_message(data)
    except(socket.timeout):
        response = 'error: timeout'
    except(socket.error):
        response = 'error: socket error'
    
    s.close()
    return response

if __name__ == '__main__':
    resolver_ip, resolver_port, name, type, timeout = parse_cmd_line(sys.argv)
    response = request_resolver(resolver_ip, resolver_port, name, type, timeout)
    print(response)
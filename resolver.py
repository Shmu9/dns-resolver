import socket
import sys
import re
from DNSmessage import DNSquery, DNSresponse

class Resolver():

    next_rootns = 0

    def __init__(self, port, filename='named.root'):
        self.port = port
        self.slist = []                             # search list (stack)
        self.sbelt = self.parse_conf(filename)      # (search) safety belt
        # self.cache = {}                             # cache (not implemented)

    def parse_conf(self, filename):
        '''
        Parse the configuration file. For the sake of simplicity, we will only parse the root NS's names.
        '''
        sbelt = []
        with open(filename, 'r') as f:
            for line in f:
                if line.startswith('.'):            # i.e. if it is a root NS
                    sbelt.append(line.split()[3])
        
        return sbelt
    
    def get_next_servername(self, look_in_sbelt=False):
        '''
        Return next root NS if look_in_sbelt is True, else return next NS from top of stack.
        Returns None if there are no more NS's to try.
        '''
        if look_in_sbelt and self.next_rootns < len(self.sbelt):
            self.next_rootns += 1
            return self.sbelt[self.next_rootns - 1]
        elif self.slist:    # not empty
            return self.slist.pop()
        else:
            return None


    def resolve(self, query):
        '''
        query is a DNSMessage.DNSQuery object. 
        Iteratively resolve the query by following authoritative name servers until an answer is found.
        Return a DNSMessage.DNSResponse object associated with the query.
        '''
        look_in_sbelt = True
        already_tried = []
        s = socket.socket(socket.AF_INET,       # IPv4
                          socket.SOCK_DGRAM)    # UDP

        while True:
            servername = self.get_next_servername(look_in_sbelt=look_in_sbelt)
            # print(f"servername: {servername}")
            if not servername:
                raise Exception('No more servers to try.')
            if servername in already_tried:
                continue
            else:
                already_tried.append(servername)
            
            s.settimeout(1)
            s.sendto(query.build_query(), (servername, 53))

            data, server = s.recvfrom(1024)     # power of 2 greater than 512

            resp = DNSresponse(query, data, checkid=True)
            if resp.ancount > 0:
                # self.slist = []     # reset search list
                # already_tried = []  # reset already tried
                s.close()
                return resp
            elif resp.aa == 1:
                # authoritative answer, but no desired record type
                s.close()
                return resp
            else:
                for r in resp.records['AUTHORITY']:
                    if r[3] == 2:  # NS record
                        if r[4] not in self.slist:
                            self.slist.append(r[4])             # NS name at index 4 (TODO: check if it's always the case; PTR records?)
                # print(f"self.slist: {self.slist}")
                
                look_in_sbelt = False if self.slist else True   # if slist is empty, look in sbelt


def usage_exit():
    print('usage: python3 resolver.py <port>')
    exit(1)


def run(udp_ip, udp_port):
    # Open singular UDP socket for client communication
    s = socket.socket(socket.AF_INET, # Internet
                      socket.SOCK_DGRAM) # UDP
    s.bind((udp_ip, udp_port))
    print(f'UDP socket awaiting queries at {udp_ip}:{udp_port}')
    while True:
        data, addr = s.recvfrom(1024)   # power of 2 greater than 512
        print('received message: %s' % data)

        resolver = Resolver(53)
        query = DNSquery()
        try:
            query.init_from_raw(data)
            resp = resolver.resolve(query)  # attempt to resolve query
            # print('\nresp.message: ')
            # print(resp.message)
            s.sendto(resp.message, addr)
        except Exception as e:
            # Corrupted or incorrect data, timeout, socket error, or no more servers to try 
            # -> let client timeout by doing nothing
            print(f'error: {e}')
            continue



if __name__ == '__main__':
    # parse cmd line
    if len(sys.argv) != 2:
        usage_exit()
    if re.match('[0-9]{1,5}', sys.argv[1]) is None:
        usage_exit()
    if int(sys.argv[1]) < 1024 or int(sys.argv[1]) > 65535:
        print(f'error: port number must be in the range 1024-65535', file=sys.stderr)
        usage_exit()
    
    udp_ip = socket.gethostbyname(socket.gethostname())
    udp_port = int(sys.argv[1])
    run(udp_ip, udp_port)
    
    
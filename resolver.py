import socket
import sys
import re

class Resolver():
    def __init__(self, port, filename='named.root'):
        self.port = port
        self.slist = []                         # search list
        sbelt = self.parse_conf(filename)       # (search) safety belt
        # self.cache = {}                         # cache


    def parse_conf(self, filename):
        '''
        For the sake of simplicity, we will only parse the root NS's names.
        '''
        sbelt = []
        with open(filename, 'r') as f:
            for line in f:
                if line.startswith('.'):        # i.e. if it is a root NS
                    sbelt.append(line.split()[3])
        return sbelt
    
    def resolve(self, query):
        '''
        query is a DNSMessage.DNSQuery object.
        '''

        s = socket.socket(socket.AF_INET,       # IPv4
                          socket.SOCK_DGRAM)    # UDP
        
        # servername = get_best_servername()
        # while DNSResponse does not contain answer:
        #   send query to servername
        #   await response
        #   if response:
        #       DNSResponse = response
        #       if DNSResponse contains answer:
        #           return DNSResponse
        #       else:
        #           self.slist = DNSResponse.get_referrals()??
        #   servername = get_best_servername() # next in cache, slist or sbelt
        #   if servername is None:
        #       raise Exception('there was no response')




        # s.settimeout(1)                         # 1 second timeout
        s.connect((servername, 53))             # UDP, so only sets default dest 
        

        # if query.QNAME in self.cache:
        #     return self.cache[query.QNAME]
        # else:
        #     # query root NS
        #     pass
        pass



def usage_exit():
    print('usage: python3 resolver.py <port>')
    exit(1)


def run(udp_ip, udp_port):
    resolver = Resolver(udp_port)
    s = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP
    s.bind((udp_ip, udp_port))
    print(f"UDP resolver awaiting queries at {udp_ip}:{udp_port}")
    # listen()?
    # block()?
    # accept()
    # read()
    # write() -> send()
    # close()

    while True:
        data, addr = s.recvfrom(1024) # buffer size is 1024 bytes
        print("received message: %s" % data)



if __name__ == '__main__':
    # parse cmd line
    if len(sys.argv) != 2:
        usage_exit()
    if re.match("[0-9]{1,5}", sys.argv[1]) is None:
        usage_exit()
    if int(sys.argv[1]) < 1024 or int(sys.argv[1]) > 65535:
        print(f"error: port number must be in the range 1024-65535", file=sys.stderr)
        usage_exit()
    
    udp_ip = socket.gethostbyname(socket.gethostname())
    udp_port = int(sys.argv[1])
    run(udp_ip, udp_port)
    
    
import random
import binascii
import struct
import socket
from util import name_from_raw, decode_question, RCODES, RECORD_CLASSES, RECORD_TYPES

# Modified from https://gist.github.com/mrpapercut/92422ecf06b5ab8e64e502da5e33b9f7
# - Implemented as class 
# - Further flexibility for different flags
# - Support for PTR queries
# - Initialisable from raw bytes
class DNSquery:
    def __init__(self, **kwargs):
        # 16-bit identifier (0-65535)
        self.ID = kwargs.get('ID', random.randint(0x0000, 0xffff))

        # 16-bit flag section
        self.QR = kwargs.get('QR', 0)           # Query: 0, Response: 1     1bit
        self.OPCODE = kwargs.get('OPCODE', 0)   # Standard query            4bit
        self.AA = kwargs.get('AA', 0)           # ?                         1bit
        self.TC = kwargs.get('TC', 0)           # Message is truncated?     1bit
        self.RD = kwargs.get('RD', 1)           # Query Recursively?        1bit
        self.RA = kwargs.get('RA', 0)           # ?                         1bit
        self.Z = kwargs.get('Z', 0)             # ?                         3bit
        self.RCODE = kwargs.get('RCODE', 0)     # Result                    4bit

        # 16-bit count section
        self.QNCOUNT = kwargs.get('QNCOUNT', 1) # Number of questions           4bit
        self.ANCOUNT = 0                        # Number of answers             4bit
        self.NSCOUNT = 0                        # Number of authority records   4bit
        self.ARCOUNT = 0                        # Number of additional records  4bit

        # query section
        self.QNAME = kwargs.get('QNAME', None) # Name to lookup
        self.QTYPE = kwargs.get('QTYPE', None) # Type of request e.g. 'A', 'NS'
        self.QCLASS = kwargs.get('QCLASS', 1)  # Class for lookup. 1 is Internet (IN)
    
    def init_from_raw(self, raw_query):
        '''
        Initialise DNSquery object from raw bytes. For use in resolver.py.
        '''
        self.ID, flags, self.QNCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT = \
            struct.unpack('!HHHHHH', raw_query[:12])     # !: big-endian, H: unsigned short (2 bytes)

        self.QR = (flags >> 15)
        self.OPCODE = (flags >> 11) & 0xf
        self.AA = (flags >> 10) & 0x1
        self.TC = (flags >> 9) & 0x1
        self.RD = (flags >> 8) & 0x1
        self.RA = (flags >> 7) & 0x1
        self.Z = (flags >> 6) & 0x1
        self.AD = (flags >> 5) & 0x1
        self.CD = (flags >> 4) & 0x1
        self.RCODE = (flags) & 0xf

        question = raw_query[12:]
        self.QNAME, self.QTYPE, self.QCLASS, _ = decode_question(question, type_as_string=True)
    
    def get_type_as_hexstring(self):
        TYPES = {
            'A': '0001',
            'NS': '0002',
            'CNAME': '0005',
            'MX': '000f',
            'PTR': '000c'
        }
        return TYPES[self.QTYPE]
    
    def get_flags_as_hexstring(self):
        flags = str(self.QR)
        flags += str(self.OPCODE).zfill(4)
        flags += str(self.AA) + str(self.TC) + str(self.RD) + str(self.RA)
        flags += str(self.Z).zfill(3)
        flags += str(self.RCODE).zfill(4)
        flags = '{:04x}'.format(int(flags, 2))

        return flags
    
    def get_name_as_hexstring(self):
        '''
        Return QNAME as hexstring. QNAME is url split up by '.', preceded by 8 bit int indicating length of part.
        '''
        name = ''

        addr_parts = self.QNAME.split('.')
        addr_parts = list(filter(lambda x: x != '', addr_parts)) # remove empty strings (for trailing '.', or root domain)
        
        if self.QTYPE == 'PTR' and \
            addr_parts[-1] != 'arpa' and addr_parts[-2] != 'in-addr': # might have already been added if init_from_raw()
            addr_parts.reverse()
            addr_parts += ['in-addr', 'arpa']

        for part in addr_parts:
            addr_len = '{:02x}'.format(len(part))
            addr_part = binascii.hexlify(part.encode())
            name += addr_len
            name += addr_part.decode()

        name += '00' # Terminating bit for QNAME
        return name

    
    def build_query(self):
        '''
        Get DNS query as bytes.
        '''
        message = '{:04x}'.format(self.ID)
        message += self.get_flags_as_hexstring()
        message += '{:04x}'.format(self.QNCOUNT)
        message += '{:04x}'.format(self.ANCOUNT)
        message += '{:04x}'.format(self.NSCOUNT)
        message += '{:04x}'.format(self.ARCOUNT)
        message += self.get_name_as_hexstring()
        message += self.get_type_as_hexstring()
        message += '{:04x}'.format(self.QCLASS)
        return bytes.fromhex(message)
    
    def __str__(self):
        return self.build_query()


    
# Modified from https://github.com/shuque/pydig/blob/master/pydiglib/dnsmsg.py
# - Simplified for subset of RR types and classes
#   - A, NS, CNAME, MX, PTR
# - Aligned formatting
# - Support for compression added manually (i.e. interpreting pointer-compressed responses)
# - Designated fields for captured resource records
# - Sets an output string in constructor
class DNSresponse:
    sections = ['QUESTION', 'ANSWER', 'AUTHORITY', 'ADDITIONAL']

    # the following are set within set_response_str()
    response_str = ''
    matches_question = False
    records = {
        'ANSWER': [],
        'AUTHORITY': [],
        'ADDITIONAL': []
    }


    def __init__(self, query, msg, checkid=True):
        self.query = query              # original DNSquery object
        self.message = msg              # byte response
        self.msglen = len(self.message)
        self.set_header(checkid)
        self.set_response_str()

    def set_header(self, checkid=True):
        '''Set header fields from response message'''
        self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount = \
            struct.unpack('!HHHHHH', self.message[:12])     # !: big-endian, H: unsigned short (2 bytes)
        if checkid and (self.id != self.query.ID):
            raise Exception('got response with id: %ld (expecting %ld)' %
                               (self.id, self.query.ID))
        self.qr = flags >> 15
        self.opcode = (flags >> 11) & 0xf
        self.aa = (flags >> 10) & 0x1
        self.tc = (flags >> 9) & 0x1
        self.rd = (flags >> 8) & 0x1
        self.ra = (flags >> 7) & 0x1
        self.z = (flags >> 6) & 0x1
        self.ad = (flags >> 5) & 0x1
        self.cd = (flags >> 4) & 0x1
        self.rcode = (flags) & 0xf

    def set_preamble(self):
        '''
        Set preamble of response string - formatted flags, counts, etc. Should only be called by constructor.
        '''
        preamble = ''
        preamble += ';; rcode=%d(%s), id=%d\n' % (self.rcode, RCODES[self.rcode], self.id)
        preamble += ';; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d\n' % \
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd)
        preamble += ';; question=%d, answer=%d, authority=%d, additional=%d\n' % \
              (self.qdcount, self.ancount, self.nscount, self.arcount)
        preamble += ';; Size: response=%d with overhead 42 (IPv4)\n' % (self.msglen)

        self.response_str += preamble

    def set_rr(self, rrname, ttl, rrtype, rrclass, rdata):
        '''
        Appends resource record to the response string. Should only be called by constructor.
        '''
        rrclass_str = RECORD_CLASSES[rrclass] if rrclass in RECORD_CLASSES else str(rrclass) + '??'
        rrtype_str = RECORD_TYPES[rrtype] if rrtype in RECORD_TYPES else str(rrtype) + '??'

        self.response_str += f'{rrname: <30}{ttl: <10}{rrclass_str: <5}{rrtype_str: <10}{rdata}\n'
        return

    def question_matched(self, qname, qtype, qclass):
        '''
        Appends warning to response string if question doesn't match answer
        '''
        if self.rcode in [0, 3]:
            if (qname.lower() == self.query.QNAME.lower()) \
                or (qname.lower() == self.query.QNAME.lower() + '.') \
                and (RECORD_TYPES[qtype] != self.query.QTYPE) \
                and (qclass != self.query.QCLASS):
                self.response_str += '*** WARNING: Answer did not the match question!\n\n'
        return
    
    def decode_rr(self, pkt, offset, secname):
        '''
        Decode a resource record, given DNS packet and offset.
        Returns domain name, resource record type, class, time-to-live and data, and new offset.
        '''

        domainname, offset = name_from_raw(pkt, offset)
        rrtype, rrclass, ttl, rdlen = \
                struct.unpack('!HHIH', pkt[offset:offset+10])
        offset += 10
        rdata = pkt[offset:offset+rdlen]
        if rrtype == 1:                                             # A
            rdata = socket.inet_ntop(socket.AF_INET, rdata)         # ipaddr
        elif rrtype in [2, 5, 12]:                                  # NS, CNAME, PTR
            rdata, _ = name_from_raw(pkt, offset)                   # domain name
        elif rrtype == 15:                                          # MX
            mx_pri, = struct.unpack('!H', pkt[offset:offset+2])     # priority
            rdata, _ = name_from_raw(pkt, offset+2)                 # domain name
            rdata = '%d %s' % (mx_pri, rdata)
        else:
            rdata = '??'
        offset += rdlen
        self.records[secname].append((domainname, ttl, rrclass, rrtype, rdata))
        return (domainname, rrtype, rrclass, ttl, rdata, offset)
    

    def set_decoded_sections(self):
        '''
        Append decoded message sections to response string. Should only be called by constructor.
        '''
        offset = 12                     # Pass through 12 byte DNS header
        answer_qname = None

        for (secname, rrcount) in zip(self.sections,
                                      [self.qdcount, self.ancount, self.nscount, self.arcount]):
            self.response_str += '\n;; %s SECTION:\n' % secname
            if secname == 'QUESTION':
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, offset = \
                            decode_question(self.message, offset=offset)
                    answer_qname = rrname
                    rrclass_str = RECORD_CLASSES[rrclass] if rrclass in RECORD_CLASSES else str(rrclass) + '??'
                    rrtype_str = RECORD_TYPES[rrtype] if rrtype in RECORD_TYPES else str(rrtype) + '??'
                    self.response_str += '%s\t%s\t%s\n' % \
                                         (answer_qname,
                                          rrclass_str,
                                          rrtype_str)
                    self.question_matched(answer_qname, rrtype, rrclass)
            else:
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, offset = self.decode_rr(self.message, offset, secname)
                    self.set_rr(rrname, ttl, rrtype, rrclass, rdata)
    
    def set_response_str(self):
        if self.rcode == 0:
            self.set_preamble()
            self.set_decoded_sections()

            aa = 'Yes' if self.aa else 'No'
            tc = 'Yes' if self.tc else 'No'
            self.response_str += '\nAuthoritative (aa): ' + aa + '\n'
            self.response_str += 'Truncated (tc): ' + tc + '\n'
            if self.ancount == 0:
                self.response_str += 'No answers found.\n'

        elif self.rcode == 1:
            self.response_str = 'Format error: the name server was unable to interpret the query.\n'
        elif self.rcode == 2:
            self.response_str = 'Server failure: the name server was unable to process this query due to a problem with the name server.\n'
        elif self.rcode == 3:
            self.response_str = 'Name Error: the domain name referenced in the query does not exist.\n'
        elif self.rcode == 4:
            self.response_str = 'Not Implemented: the name server does not support the requested kind of query.\n'
        elif self.rcode == 5:
            self.response_str = 'Refused: the name server refuses to perform the specified operation for policy reasons.\n'
        else:
            self.response_str = 'Unknown response code: {}.\n' % (self.rcode)
    
    def __str__(self):
        return self.response_str
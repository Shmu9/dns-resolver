import random
import binascii
from collections import OrderedDict
import struct
import socket

RECORD_TYPES = {
    # 0: "RESERVED",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX"
}

RECORD_CLASSES ={
    1: "IN",
    # 2: "CS",
    # 3: "CH",
    # 4: "HS"
    # 255: "*"
}

# DNS Response Codes (Bijective?)
RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMPL",
    5: "REFUSED",
    9: "NOTAUTH",
    16: "BADVERS",
    17: "BADKEY",
    18: "BADTIME",
    19: "BADMODE",
    20: "BADNAME",
    21: "BADALG",
    22: "BADTRUNC",
    23: "BADCOOKIE"
    # "FORMERR": 1,
    # "SERVFAIL": 2,
    # "NXDOMAIN": 3,
    # "NOTIMPL": 4,
    # "REFUSED": 5,
    # "NOTAUTH": 9,
    # "BADVERS": 16,
    # "BADKEY": 17,
    # "BADTIME": 18,
    # "BADMODE": 19,
    # "BADNAME": 20,
    # "BADALG": 21,
    # "BADTRUNC": 22,
    # "BADCOOKIE": 23,
}

# Modified from https://gist.github.com/mrpapercut/92422ecf06b5ab8e64e502da5e33b9f7
# - Implemented as class 
# - Further flexibility for different flags
# - Support for PTR queries
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
        self.ANCOUNT = kwargs.get('ANCOUNT', 0) # Number of answers             4bit
        self.NSCOUNT = kwargs.get('NSCOUNT', 0) # Number of authority records   4bit
        self.ARCOUNT = kwargs.get('ARCOUNT', 0) # Number of additional records  4bit

        # query section
        self.QNAME = kwargs.get('QNAME', None) # Name to lookup
        self.QTYPE = kwargs.get('QTYPE', None) # Type of request e.g. 'A', 'NS'
        self.QCLASS = kwargs.get('QCLASS', 1)  # Class for lookup. 1 is Internet (IN)
    
    def init_from_raw(self, raw_query):
        """Decode a DNS protocol header"""
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
        # print(self.ID, self.QR, self.OPCODE, self.AA, self.TC, self.RD, self.RA, self.Z, self.AD, self.CD, self.RCODE, self.QNCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)

        question = raw_query[12:]
        self.QNAME, self.QTYPE, self.QCLASS = self.decode_question(question)
        # print(self.QNAME, self.QTYPE, self.QCLASS)

    def decode_question(self, question):
        """decode question section of a DNS message"""
        name, offset = self.name_from_wire_message(question, 0)
        qtype, qclass = struct.unpack("!HH", question[offset:offset+4])
        qtype = RECORD_TYPES[qtype] if qtype in RECORD_TYPES else str(qtype) + "??"
        # qclass = RECORD_CLASSES[qclass] if qclass in RECORD_CLASSES else str(qclass) + "??"
        return (name, qtype, qclass)
    
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
        flags = "{:04x}".format(int(flags, 2))

        return flags
    
    def get_name_as_hexstring(self):
        '''
        Return QNAME as hexstring. QNAME is url split up by '.', preceded by 8 bit int indicating length of part.
        '''
        name = ""

        addr_parts = self.QNAME.split(".")
        addr_parts = list(filter(lambda x: x != '', addr_parts)) # remove empty strings (for trailing '.', or root domain)
        
        if self.QTYPE == 'PTR':
            addr_parts.reverse()
            addr_parts += ['in-addr', 'arpa']

        for part in addr_parts:
            addr_len = "{:02x}".format(len(part))
            addr_part = binascii.hexlify(part.encode())
            name += addr_len
            name += addr_part.decode()

        name += "00" # Terminating bit for QNAME
        return name

    
    def build_query(self):
        '''
        Get DNS query as bytes.
        '''
        message = "{:04x}".format(self.ID)
        message += self.get_flags_as_hexstring()
        message += "{:04x}".format(self.QNCOUNT)
        message += "{:04x}".format(self.ANCOUNT)
        message += "{:04x}".format(self.NSCOUNT)
        message += "{:04x}".format(self.ARCOUNT)
        message += self.get_name_as_hexstring()
        message += self.get_type_as_hexstring()
        message += "{:04x}".format(self.QCLASS)
        return bytes.fromhex(message)
    
    def __repr__(self):
        return "<DNSquery: {},{},{}>".format(self.qname, self.qtype, self.qclass)
    
    def __str__(self):
        return self.build_query()
    
    def name_from_wire_message(self, msg, offset):
        """
        Given wire format message, return a Name() object corresponding to the
        domain name at given offset in the message.
        """
        labels, offset = self.get_name_labels(msg, offset, [])
        return self.labels2text(labels), offset


    def get_name_labels(self, msg, offset, compression_offsets):

        """
        Decode domain name at given packet offset. compression_offsets is a list
        of compression offsets seen so far. Returns list of domain name labels.
        """

        labellist = []
        Done = False
        while not Done:
            llen, = struct.unpack('B', msg[offset:offset+1])
            if (llen >> 6) == 0x3:                  # compression pointer starts with 2 1 bits, RFC1035 4.1.4
                self.compression_count += 1         # perhaps redundant??
                compression_offset = struct.unpack('!H', msg[offset:offset+2])[0] & 0x3fff
                if compression_offset in compression_offsets:
                    raise Exception('Compression pointer loop detected.')
                compression_offsets.append(compression_offset)
                offset += 2
                rightmostlabels, _ = self.get_name_labels(msg, compression_offset, compression_offsets)
                labellist += rightmostlabels
                Done = True
            else:
                offset += 1
                label = msg[offset:offset+llen]
                offset += llen
                labellist.append(label)
                if llen == 0:
                    Done = True
        return (labellist, offset)
    
    def labels2text(self, labels):
        """Return textual representation of domain name."""
        name_parts = []
        for label in labels:
            part = ''
            for c in label:
                char = chr(c)
                if c in b'.\\':
                    part += ("\\" + char)
                elif c > 32 and c < 127:            # printable ascii
                    part += char
                else:
                    part += "\\{:03d}".format(c)    # as decimal (0-128)
            name_parts.append(part)

        if name_parts == ['']:
            return "."
        return ".".join(name_parts)


    
# Modified from https://github.com/shuque/pydig/blob/master/pydiglib/dnsmsg.py
# - Simplified for subset of RR types and classes
#   - A, NS, CNAME, MX, PTR
# - Aligned formatting
# - Support for compression added manually (i.e. interpreting pointer-compressed responses)
# - Designated fields for captured resource records
class DNSresponse:
    """DNS Response class"""

    sections = ["QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"]

    # the following are set within set_response_str()
    compression_count = 0
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
        self.decode_header(checkid)
        self.set_response_str()

    def decode_header(self, checkid=True):
        """Decode a DNS protocol header"""
        self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount = \
            struct.unpack('!HHHHHH', self.message[:12])     # !: big-endian, H: unsigned short (2 bytes)
        if checkid and (self.id != self.query.ID):
            # Should continue listening for a valid response here (ideally)
            raise Exception("got response with id: %ld (expecting %ld)" %
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

    def append_to_response_str(self, str, print=False):
        if print:
            print(str)
        else:
            self.response_str += str + "\n"

    def print_preamble(self):
        """Print preamble of a DNS response message"""
        self.append_to_response_str(";; rcode=%d(%s), id=%d" %
              (self.rcode, RCODES[self.rcode], self.id))
        self.append_to_response_str(";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" %
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd))
        self.append_to_response_str(";; question=%d, answer=%d, authority=%d, additional=%d" %
              (self.qdcount, self.ancount, self.nscount, self.arcount))
        self.append_to_response_str(";; Size: response=%d with overhead 42 (IPv4)" % (self.msglen))

    def print_rr(self, rrname, ttl, rrtype, rrclass, rdata):
        """Print RR in presentation format"""
        rrclass_str = RECORD_CLASSES[rrclass] if rrclass in RECORD_CLASSES else str(rrclass) + "??"
        rrtype_str = RECORD_TYPES[rrtype] if rrtype in RECORD_TYPES else str(rrtype) + "??"

        self.append_to_response_str(f"{rrname: <30}{ttl: <10}{rrclass_str: <5}{rrtype_str: <10}{rdata}")
        return

    def decode_question(self, offset):
        """decode question section of a DNS message"""
        domainname, offset = self.name_from_wire_message(self.message, offset)
        rrtype, rrclass = struct.unpack("!HH", self.message[offset:offset+4])
        offset += 4
        return (domainname, rrtype, rrclass, offset)

    def question_matched(self, qname, qtype, qclass):
        """Check that answer matches question"""
        if self.rcode in [0, 3]:
            if (qname.lower() == self.query.QNAME.lower()) \
                or (qname.lower() == self.query.QNAME.lower() + ".") \
                and (RECORD_TYPES[qtype] != self.query.QTYPE) \
                and (qclass != self.query.QCLASS):
                self.append_to_response_str("*** WARNING: Answer didn't match question!\n")
        return
    
    def decode_rr(self, pkt, offset, secname):
        """ Decode a resource record, given DNS packet and offset"""
        # data must be in bytes

        domainname, offset = self.name_from_wire_message(pkt, offset)
        rrtype, rrclass, ttl, rdlen = \
                struct.unpack("!HHIH", pkt[offset:offset+10])
        offset += 10
        rdata = pkt[offset:offset+rdlen]
        if rrtype == 1:                                             # A
            rdata = socket.inet_ntop(socket.AF_INET, rdata)         # ipaddr
        elif rrtype in [2, 5, 12]:                                  # NS, CNAME, PTR
            rdata, _ = self.name_from_wire_message(pkt, offset)     # domain name
        elif rrtype == 15:                                          # MX
            mx_pri, = struct.unpack('!H', pkt[offset:offset+2])     # priority
            rdata, _ = self.name_from_wire_message(pkt, offset+2)   # domain name
            rdata = "%d %s" % (mx_pri, rdata)
        else:
            rdata = "??"
            # raise Exception('Unknown resource record type %d.\nOnly A, NS, CNAME, PTR, MX supported.' % rrtype)
        offset += rdlen
        self.records[secname].append((domainname, ttl, rrclass, rrtype, rdata))
        return (domainname, rrtype, rrclass, ttl, rdata, offset)
    
    def name_from_wire_message(self, msg, offset):
        """
        Given wire format message, return a Name() object corresponding to the
        domain name at given offset in the message.
        """
        labels, offset = self.get_name_labels(msg, offset, [])
        return self.labels2text(labels), offset


    def get_name_labels(self, msg, offset, compression_offsets):

        """
        Decode domain name at given packet offset. compression_offsets is a list
        of compression offsets seen so far. Returns list of domain name labels.
        """

        labellist = []
        Done = False
        while not Done:
            llen, = struct.unpack('B', msg[offset:offset+1])
            if (llen >> 6) == 0x3:                  # compression pointer starts with 2 1 bits, RFC1035 4.1.4
                self.compression_count += 1         # perhaps redundant??
                compression_offset = struct.unpack('!H', msg[offset:offset+2])[0] & 0x3fff
                if compression_offset in compression_offsets:
                    raise Exception('Compression pointer loop detected.')
                compression_offsets.append(compression_offset)
                offset += 2
                rightmostlabels, _ = self.get_name_labels(msg, compression_offset, compression_offsets)
                labellist += rightmostlabels
                Done = True
            else:
                offset += 1
                label = msg[offset:offset+llen]
                offset += llen
                labellist.append(label)
                if llen == 0:
                    Done = True
        return (labellist, offset)
    
    def labels2text(self, labels):
        """Return textual representation of domain name."""
        name_parts = []
        for label in labels:
            part = ''
            for c in label:
                char = chr(c)
                if c in b'.\\':
                    part += ("\\" + char)
                elif c > 32 and c < 127:            # printable ascii
                    part += char
                else:
                    part += "\\{:03d}".format(c)    # as decimal (0-128)
            name_parts.append(part)

        if name_parts == ['']:
            return "."
        return ".".join(name_parts)

    def decode_sections(self):
        """Decode message sections and print contents"""
        offset = 12                     # skip over DNS header (12 bytes)
        answer_qname = None

        for (secname, rrcount) in zip(self.sections,
                                      [self.qdcount, self.ancount, self.nscount, self.arcount]):
            self.append_to_response_str("\n;; %s SECTION:" % secname)
            if secname == "QUESTION":
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, offset = \
                            self.decode_question(offset)
                    answer_qname = rrname
                    rrclass_str = RECORD_CLASSES[rrclass] if rrclass in RECORD_CLASSES else str(rrclass) + "??"
                    rrtype_str = RECORD_TYPES[rrtype] if rrtype in RECORD_TYPES else str(rrtype) + "??"
                    self.append_to_response_str("%s\t%s\t%s" % (answer_qname,
                                          rrclass_str,
                                          rrtype_str))
                    self.question_matched(answer_qname, rrtype, rrclass)
            else:
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, offset = self.decode_rr(self.message, offset, secname)
                    self.print_rr(rrname, ttl, rrtype, rrclass, rdata)

    def print_all(self):
        """Print all info about the DNS response message"""
        self.print_preamble()
        self.decode_sections()
    
    def set_response_str(self):
        self.print_preamble()
        self.decode_sections()

        aa = 'Yes' if self.aa else 'No'
        tc = 'Yes' if self.tc else 'No'
        self.response_str += "\nAuthoritative (aa): " + aa + "\n"
        self.response_str += "Truncated (tc): " + tc + "\n"

    def __repr__(self):
        return "<DNSresponse: {},{},{}>".format(
            self.query.QNAME, self.query.QTYPE, self.query.QCLASS)
    
    def __str__(self):
        return self.response_str
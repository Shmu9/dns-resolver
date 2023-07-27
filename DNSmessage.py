import random
import binascii
from collections import OrderedDict
import struct
import socket

RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
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

# DNS Response Codes
RCODES = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMPL": 4,
    "REFUSED": 5,
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
# - Further flexibility for different types of queries
class DNSquery:
    def __init__(self, **kwargs):
        # 16-bit identifier (0-65535)
        self.ID = kwargs.get('ID', random.randint(0, 65535))

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
        self.QSTNCOUNT = kwargs.get('QSTNCOUNT', 1) # Number of questions           4bit
        self.ANSRCOUNT = kwargs.get('ANSRCOUNT', 0) # Number of answers             4bit
        self.AUTHCOUNT = kwargs.get('AUTHCOUNT', 0) # Number of authority records   4bit
        self.ADDICOUNT = kwargs.get('ADDICOUNT', 0) # Number of additional records  4bit

        # query section
        self.QNAME = kwargs.get('QNAME', None) # URL to lookup
        self.QTYPE = kwargs.get('QTYPE', None) # Type of request e.g. 'A', 'NS'
        self.QCLASS = kwargs.get('QCLASS', 1)  # Class for lookup. 1 is Internet
    
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
        name = ""
        # QNAME is url split up by '.', preceded by 8 bit? int indicating length of part
        addr_parts = self.QNAME.split(".")
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
        message += "{:04x}".format(self.QSTNCOUNT)
        message += "{:04x}".format(self.ANSRCOUNT)
        message += "{:04x}".format(self.AUTHCOUNT)
        message += "{:04x}".format(self.ADDICOUNT)
        message += self.get_name_as_hexstring()
        message += self.get_type_as_hexstring()
        message += "{:04x}".format(self.QCLASS)
        print(message)
        return bytes.fromhex(message)
    
    def decode_message(self, message):
        message = binascii.hexlify(message).decode()
        res = []
        
        ID              = message[0:4]
        query_params    = message[4:8]
        QSTNCOUNT       = message[8:12]
        ANSRCOUNT       = message[12:16]
        AUTHCOUNT       = message[16:20]
        ADDICOUNT       = message[20:24]

        params = "{:b}".format(int(query_params, 16)).zfill(16)
        QPARAMS = OrderedDict([
            ("QR", params[0:1]),
            ("OPCODE", params[1:5]),
            ("AA", params[5:6]),
            ("TC", params[6:7]),
            ("RD", params[7:8]),
            ("RA", params[8:9]),
            ("Z", params[9:12]),
            ("RCODE", params[12:16])
        ])

        # Question section
        QUESTION_SECTION_STARTS = 24
        question_parts = self.parse_parts(message, QUESTION_SECTION_STARTS, [])
        
        QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), question_parts))    

        QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
        QCLASS_STARTS = QTYPE_STARTS + 4

        QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
        QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]
        
        res.append("\n# HEADER")
        res.append("ID: " + ID)
        res.append("QUERYPARAMS: ")
        for qp in QPARAMS:
            res.append(" - " + qp + ": " + QPARAMS[qp])
        res.append("\n# QUESTION SECTION")
        res.append("QNAME: " + QNAME)
        res.append("QTYPE: " + QTYPE + " (\"" + self.get_type_as_hexstring() + "\")")
        res.append("QCLASS: " + QCLASS)

        # Answer section
        ANSWER_SECTION_STARTS = QCLASS_STARTS + 4
        
        NUM_ANSWERS = max([int(ANSRCOUNT, 16), int(AUTHCOUNT, 16), int(ADDICOUNT, 16)])
        if NUM_ANSWERS > 0:
            res.append("\n# ANSWER SECTION")
            
            for ANSWER_COUNT in range(NUM_ANSWERS):
                if (ANSWER_SECTION_STARTS < len(message)):
                    ANAME = message[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4] # Refers to Question
                    ATYPE = message[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                    ACLASS = message[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
                    TTL = int(message[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
                    RDLENGTH = int(message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                    RDDATA = message[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                    if ATYPE == self.get_type_as_hexstring():
                        octets = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
                        RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
                    else:
                        RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), self.parse_parts(RDDATA, 0, [])))
                        
                    ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

                try: ATYPE
                except NameError: None
                else:  
                    res.append("# ANSWER " + str(ANSWER_COUNT + 1))
                    res.append("QSTNCOUNT: " + str(int(QSTNCOUNT, 16)))
                    res.append("ANSRCOUNT: " + str(int(ANSRCOUNT, 16)))
                    res.append("AUTHCOUNT: " + str(int(AUTHCOUNT, 16)))
                    res.append("ADDICOUNT: " + str(int(ADDICOUNT, 16)))
                    
                    res.append("ANAME: " + ANAME)
                    res.append("ATYPE: " + ATYPE + " (\"" + self.get_type_as_hexstring() + "\")")
                    res.append("ACLASS: " + ACLASS)
                    
                    res.append("\nTTL: " + str(TTL))
                    res.append("RDLENGTH: " + str(RDLENGTH))
                    res.append("RDDATA: " + RDDATA)
                    res.append("RDDATA decoded (result): " + RDDATA_decoded + "\n")

        return "\n".join(res)

    def parse_parts(self, message, start, parts):
        part_start = start + 2
        part_len = message[start:part_start]
        
        if len(part_len) == 0:
            return parts
        
        part_end = part_start + (int(part_len, 16) * 2)
        parts.append(message[part_start:part_end])

        if message[part_end:part_end + 2] == "00" or part_end > len(message):
            return parts
        else:
            return self.parse_parts(message, part_end, parts)
    
# Modified from https://github.com/shuque/pydig/blob/master/pydiglib/dnsmsg.py
# - Simplified for subset of RR types and classes
#   - A, NS, CNAME, MX, PTR
# - Support for compression added manually (i.e. interpreting pointer-compressed responses)
class DNSresponse:
    """DNS Response class"""

    sections = ["QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"]
    compression_count = 0

    def __init__(self, query, msg, checkid=True):
        self.query = query              # original DNSquery object
        self.message = msg
        self.msglen = len(self.message)
        self.decode_header(checkid)

    def decode_header(self, checkid=True):
        """Decode a DNS protocol header"""
        self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount = \
            struct.unpack('!HHHHHH', self.message[:12])
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

    def print_preamble(self):
        """Print preamble of a DNS response message"""
        print(";; rcode=%d(%s), id=%d" %
              (self.rcode, RCODES[self.rcode], self.id))
        print(";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" %
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd))
        print(";; question=%d, answer=%d, authority=%d, additional=%d" %
              (self.qdcount, self.ancount, self.nscount, self.arcount))
        print(";; Size response=%d with overhead 42" % (self.msglen))

    def print_rr(self, rrname, ttl, rrtype, rrclass, rdata):
        """Print RR in presentation format"""
        print("%s\t%d\t%s\t%s\t%s" %
              (rrname.text(), ttl, RECORD_CLASSES[rrclass], RECORD_TYPES[rrtype], rdata))
        return

    def decode_question(self, offset):
        """decode question section of a DNS message"""
        domainname, offset = name_from_wire_message(self.message, offset)
        rrtype, rrclass = struct.unpack("!HH", self.message[offset:offset+4])
        offset += 4
        return (domainname, rrtype, rrclass, offset)

    def question_matched(self, qname, qtype, qclass):
        """Check that answer matches question"""
        if self.rcode in [0, 3]:
            if (qname.lower() == self.query.QNAME.lower()) \
                or (qtype != self.query.QTYPE) \
                or (qclass != self.query.QCLASS):
                print("*** WARNING: Answer didn't match question!\n")
        return
    
    def decode_rr(pkt, offset):
        """ Decode a resource record, given DNS packet and offset"""
        # data must be in bytes

        domainname, offset = self.name_from_wire_message(pkt, offset)
        rrtype, rrclass, ttl, rdlen = \
                struct.unpack("!HHIH", pkt[offset:offset+10])
        offset += 10
        rdata = pkt[offset:offset+rdlen]
        if rrtype == 1:                                          # A
            rdata = socket.inet_ntop(socket.AF_INET, rdata)
        elif rrtype in [2, 5, 12]:                               # NS, CNAME, PTR
            rdata, _ = self.name_from_wire_message(pkt, offset)
            rdata = rdata.text()
        elif rrtype == 15:                                       # MX
            mx_pref, = struct.unpack('!H', pkt[offset:offset+2])
            rdata, _ = self.name_from_wire_message(pkt, offset+2)
            rdata = "%d %s" % (mx_pref, rdata.text())
        else:
            raise Exception('Unknown resource record type %d.\nOnly A, NS, CNAME, PTR, MX supported.' % rrtype)
        offset += rdlen
        return (domainname, rrtype, rrclass, ttl, rdata, offset)
    
    def name_from_wire_message(self, msg, offset):
        """
        Given wire format message, return a Name() object corresponding to the
        domain name at given offset in the message.
        """
        labels, offset = get_name_labels(self, msg, offset, [])
        return Name(labels), offset


    def get_name_labels(self, msg, offset, c_offset_list):

        """
        Decode domain name at given packet offset. c_offset_list is a list
        of compression offsets seen so far. Returns list of domain name labels.
        """

        labellist = []
        Done = False
        while not Done:
            llen, = struct.unpack('B', msg[offset:offset+1])
            if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
                self.compression_count += 1
                c_offset = struct.unpack('!H', msg[offset:offset+2])[0] & 0x3fff
                if c_offset in c_offset_list:
                    raise Exception("Found compression pointer loop.")
                c_offset_list.append(c_offset)
                offset += 2
                rightmostlabels, _ = get_name_labels(msg, c_offset, c_offset_list)
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
    
    def name2text(self, labels):
        """Return textual representation of domain name."""
        result_list = []

        for label in labels:
            result = bytes2escapedstring(label, backslash_label, printables_label)
            result_list.append(result)

        if result_list == ['']:
            return "."
        return ".".join(result_list)



    def decode_sections(self):
        """Decode message sections and print contents"""
        offset = 12                     # skip over DNS header
        answer_qname = None

        for (secname, rrcount) in zip(self.sections,
                                      [self.qdcount, self.ancount, self.nscount, self.arcount]):
            print("\n;; %s SECTION:" % secname)
            if secname == "QUESTION":
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, offset = \
                            self.decode_question(offset)
                    answer_qname = rrname
                    print("%s\t%s\t%s" % (answer_qname.text(),
                                          RECORD_CLASSES[rrclass],
                                          RECORD_TYPES[rrtype]))
                    self.question_matched(answer_qname, rrtype, rrclass)
            else:
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, offset = decode_rr(self.message, offset)
                    self.print_rr(rrname, ttl, rrtype, rrclass, rdata)

    def print_all(self):
        """Print all info about the DNS response message"""
        self.print_preamble()
        self.decode_sections()

    def __repr__(self):
        return "<DNSresponse: {},{},{}>".format(
            self.query.QNAME, self.query.QTYPE, self.query.QCLASS)
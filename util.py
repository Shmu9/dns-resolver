import struct

# DNS Record/Query Types
RECORD_TYPES = {
    # 0: "RESERVED",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX"
}

# DNS Record/Query Classes
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


def name_from_raw(pkt, offset):
    '''
    Return a resource record name as a string corresponding to the
    domain name at given offset in a raw packet. e.g. www.google.com.
    '''

    labels, offset = get_name_labels(pkt, offset, [])
    return labels2text(labels), offset


def get_name_labels(msg, offset, compression_offsets):

    """
    Decode domain name at given packet offset. compression_offsets is a list
    of compression offsets seen so far. Returns list of domain name labels.
    """

    labellist = []
    Done = False
    while not Done:
        llen, = struct.unpack('B', msg[offset:offset+1])
        if (llen >> 6) == 0x3:                  # compression pointer starts with 2 1 bits, RFC1035 4.1.4
            compression_offset = struct.unpack('!H', msg[offset:offset+2])[0] & 0x3fff
            if compression_offset in compression_offsets:
                raise Exception('Compression pointer loop detected.')
            compression_offsets.append(compression_offset)
            offset += 2
            rightmostlabels, _ = get_name_labels(msg, compression_offset, compression_offsets)
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

def labels2text(labels):
    '''
    Convert list of labels to a domain name string. e.g. www.google.com.
    '''
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

def decode_question(pkt, offset=0, type_as_string=False):
    '''
    Decode a DNS question from a raw packet at given offset.
    Returns a resource record name, qtype/rrtype, qclass/rrclass and new offset.
    '''
    rrname, offset = name_from_raw(pkt, offset)
    qtype, qclass = struct.unpack("!HH", pkt[offset:offset+4])
    offset += 4
    if type_as_string: 
        qtype = RECORD_TYPES[qtype] if qtype in RECORD_TYPES else str(qtype) + "??"
    return (rrname, qtype, qclass, offset)
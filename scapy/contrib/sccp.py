#! /usr/bin/env python
#
# Copyright (C) 2019 Thanos Gkantsidis <gkantsidis@niometrics.com>
#

# scapy.contrib.description = Signalling Connection Control Part (SCCP)
# scapy.contrib.status = loads
# scapy.contrib.name = SCCP

import socket
import struct
from time import ctime

from scapy.packet import Packet, bind_layers, bind_bottom_up, bind_top_down
from scapy.fields import ConditionalField, EnumField, Field, FieldLenField, \
    FlagsField, IEEEDoubleField, IEEEFloatField, IntEnumField, IntField, \
    LongField, PacketListField, SignedIntField, StrLenField, X3BytesField, \
    XByteField, XIntField,XByteEnumField,XShortField,XStrFixedLenField,StrFixedLenField
from scapy.layers.mtp3 import TransferMessage
import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.compat import chb, orb, raw, bytes_hex, plain_str
from scapy.error import warning
from scapy.utils import inet_ntoa, inet_aton
from scapy.pton_ntop import inet_pton, inet_ntop



TBCD_TO_ASCII = b"0123456789*#abc"
class TBCDByteField(StrFixedLenField):

    def i2h(self, pkt, val):
        return val

    def m2i(self, pkt, val):
        ret = []
        for v in val:
            byte = orb(v)
            left = byte >> 4
            right = byte & 0xf
            if left == 0xf:
                ret.append(TBCD_TO_ASCII[right:right + 1])
            else:
                ret += [TBCD_TO_ASCII[right:right + 1], TBCD_TO_ASCII[left:left + 1]]  # noqa: E501
        return b"".join(ret)

    def i2m(self, pkt, val):
        val = str(val)
        ret_string = ""
        for i in range(0, len(val), 2):
            tmp = val[i:i + 2]
            if len(tmp) == 2:
                ret_string += chr(int(tmp[1] + tmp[0], 16))
            else:
                ret_string += chr(int("F" + tmp[0], 16))
        return ret_string


class SCCP(Packet):
    name = "SCCP"
    fields_desc = [
        XByteField("type", 1),
        XByteField("class", 1),
        XByteField("pointer1", 1),
        XByteField("pointer2", 1),
        XByteField("pointer3", 1),
        XStrFixedLenField("padding", "", 6),
        TBCDByteField("called_address", "", 6),
        XStrFixedLenField("padding2", "", 6),
        TBCDByteField("calling_address", "", 6),
    ]


bind_layers(TransferMessage, SCCP, SI=3)

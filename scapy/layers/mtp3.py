#! /usr/bin/env python
#
# Copyright (C) 2019 Thanos Gkantsidis <gkantsidis@niometrics.com>
#

# scapy.contrib.description = MTP3-User Adaptation (MTP3)
# scapy.contrib.status = loads
# scapy.contrib.name = MTP3

import socket
import struct
from time import ctime

from scapy.packet import bind_layers, bind_bottom_up, bind_top_down, \
    Packet, Raw
from scapy.fields import ConditionalField, EnumField, Field, FieldLenField, \
    FlagsField, IEEEDoubleField, IEEEFloatField, IntEnumField, IntField, \
    LongField, PacketListField, SignedIntField, StrLenField, X3BytesField, \
    XByteField, XIntField,XByteEnumField,XShortField,XShortEnumField
from scapy.layers.sctp import SCTPChunkData
from scapy.layers.sctp import SCTP
import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.compat import chb, orb, raw, bytes_hex, plain_str
from scapy.error import warning
from scapy.utils import inet_ntoa, inet_aton
from scapy.pton_ntop import inet_pton, inet_ntop

MessageClassEnum = {
        0 : "Management (MGMT) Messages",
        1 : "Transfer Messages,",
        2 : "SS7 Signalling Network Management (SSNM) Messages",
        3 : "ASP State Maintenance (ASPSM) Messages",
        4 : "ASP Traffic Maintenance (ASPTM) Messages",
        5 : "Reserved for Other SIGTRAN Adaptation Layers",
        6 : "Reserved for Other SIGTRAN Adaptation Layers",
        7 : "Reserved for Other SIGTRAN Adaptation Layers",
        8 : "Reserved for Other SIGTRAN Adaptation Layers",
        9 : "Routing Key Management (RKM) Messages",
}

MessageTypeMGMTEnum = {
        0 : "Error",
        1 : "Notify",
}

MessageTypeTransferEnum = {
        1 : "Payload Data (DATA)",
}

M3UASpecificParameters = {
    0x0200 : "Network Appearance",                     
    0x0204 : "User/Cause",                  
    0x0205 : "Congestion Indications",      
    0x0206 : "Concerned Destination",   
    0x0207 : "Routing Key",
    0x0208 : "Registration Result",    
    0x0209 : "Deregistration Result",       
    0x020a : "Local Routing Key Identifier",
    0x020b : "Destination Point Code",
    0x020c : "Service Indicators",                  
    0x020e : "Originating Point Code List",
    0x0210 : "Protocol Data",                                  
    0x0212 : "Registration Status",        
    0x0213 : "Deregistration Status"       
}

class TransferMessage(Packet):
    name = "Transfer Message"
    fields_desc = [
        XShortEnumField("tag", 1, M3UASpecificParameters),
        XShortField("len", 1),
        XIntField("opc", 1),
        XIntField("dpc", 1),
        XByteField("SI", 1),
        XByteField("NI", 1),
        XByteField("MP", 1),
        XByteField("SLS", 1)
    ]

class MTP3(Packet):
    name = "MTP3"
    fields_desc = [
        XByteField("version", 1),
        XByteField("reserved", 1),
        XByteEnumField("class", 1, MessageClassEnum),
        XByteField("type", 1),
        XIntField("len",1),
        PacketListField(
            "parameters",
            [],
            TransferMessage,
            length_from=lambda pkt: pkt.len - 8
        )
    ]


bind_layers(SCTPChunkData, MTP3, proto_id=3)
bind_layers(MTP3, SCTPChunkData, version=1)

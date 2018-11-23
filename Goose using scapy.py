import struct
import binascii
import datetime
from datetime import timedelta
from socket import *
import sys
import re
from scapy.all import *

data_set = [(b'Dataset')]

numbera = 0
while numbera < 10:
    pkt = sniff(filter = "ether proto 0x88b8", iface = 'Realtek PCIe GBE Family Controller',count = 1)
    d = pkt[0]
    data = raw(d)
    
    if True:
        print('\nDest mac:',binascii.hexlify(data[:6]))
        print('Src mac:',binascii.hexlify(data[6:12]))
        print('Ether type (GOOSE:88-B8):',binascii.hexlify(data[12:14]))
        print('APPID (0000 to 3FFF for GOOSE):',binascii.hexlify(data[14:16]))
        print('lenngth (lenngth of APDU + 8 in OCTET):',binascii.hexlify(data[16:18]),':',int ((binascii.hexlify(data[16:17])),16))
        print('Reserved1 (GOOSE:00 00):',binascii.hexlify(data[18:20]))
        print('Reserved2 (GOOSE:00 00):',binascii.hexlify(data[20:22]))
        print('GOOSE PDU Tag:',binascii.hexlify(data[22:23]))
        i = 22
        start = 22
        while i < len(data):
            if data[i:i+1] == b'\x80':
                start = i
                i = len(data)+10
            else:
                i = i + 1
        lenn = struct.unpack('!B' , data[start+1:start+2])
        gocbreflenn = lenn[0]
        a = '!'+str(gocbreflenn)+'s'
        gocbref = struct.unpack(a,data[start+2:(start+2+gocbreflenn)])
        print('GOOSE ref :',gocbref[0])
        end = start+2+gocbreflenn
        
        #data 2
        start = end
        lenn = struct.unpack('!B' , data[start + 1:start + 2])
        timetolivelenn = lenn[0]
        a = '!'+str(timetolivelenn)+'s'
        timetolive = int ((binascii.hexlify(data[start+2:start+2+timetolivelenn])),16)
        print('Time to live :',timetolive)
        end = start+2+timetolivelenn
        #data 3
        start = end
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = struct.unpack(a,data[start+2:end+2])
        i = 0
        data_set_len = len (data_set)
        while i < len(data_set):
            if data_set[i] == value[0]:
                i = data_set_len +10
            if i == data_set_len - 1:
                print ('appending')
                data_set.append(value[0])
            i = i + 1
        
        #data 4
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = struct.unpack(a,data[start+2:end+2])
        print('goID :',value[0])

        #data 5
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        timdrift = int ((binascii.hexlify(data[start+2:start+6])),16)
        starttime = datetime(1970, 1, 1, 0, 0, 0, 0)
        timdriftmil = int ((binascii.hexlify(data[start+6:start+10])),16)
        binary = bin(timdriftmil)
        bina = binary[2:].zfill(32)
        i = 0
        v = 0
        while i < 32:
            v = v + ((2**(-(i+1)))*int(bina[i]))
            i = i+1
        tim = (starttime+timedelta(seconds= timdrift+v))
        print('Time:',tim)
        

        #data 6
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('St Num:',value)

        #data 7
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('Sq Num:',value)

        #data 8
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('Test:',value)

        #data 9
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('Conf Rev:',value)

        #data 10
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('ndsCom:',value)

        #data 11
        start = end+2
        lenn = struct.unpack('!B' , data[start+1:start+2])
        lenn = lenn[0]
        end = start + lenn
        a = '!'+str(lenn)+'s'
        value = int ((binascii.hexlify(data[start+2:end+2])),16)
        print('Num data set entry:',value)

        # Goose values
        i = 1
        start = end+2
        while start < len(data):
            if data[start] == 131:
                if data[start+2] == 1:
                    torf = 'True'
                else:
                    torf = 'False'
                print('Goose status, int',i,'=',torf,'(', data[start+2],')')
                start = start + 3
                i = i + 1
            else:
                start = start+1

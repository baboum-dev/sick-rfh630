#!/usr/bin/python
# vim: set fileencoding=utf-8 et sts=4 sw=4:
from __future__ import absolute_import, division, print_function, unicode_literals
from datetime import date, datetime
import six
"""
  RFID Sick RFH-630
"""

from socket import socket, AF_INET, SOCK_STREAM
from time import sleep
from collections import namedtuple
from itertools import groupby
import math
from threading import Thread, Event, Lock 

import coloredlogs, logging
logger = logging.getLogger(__name__)
coloredlogs.install(logger=logger, isatty=True, level=logging.DEBUG)
from pprint import pformat

STX = chr(2).encode()
ETX = chr(3).encode()

HOST = '192.168.216.212'
PORT = 2111

def convertToHexString(hex_value):
    hex_int = int(hex_value, 16)
    new_int = hex_int + 0x200
    return hex(new_int)[3:].upper()

class RFH630():
    def __init__( self, host, port, verbose=False):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect((host, port))
        self._reader = self.msg_generator()
        self.verbose=verbose

    def __del__( self ):
        self.socket.close()

    def msg_generator(self):
        data=b''
        while True:
            data += self.socket.recv(1024)
            if data:
                blocks=data.split(ETX)
                #if data ends with ETX, last block will be ''
                # otherwise data ends with unterminated packet, keep it in buffer
                data=blocks.pop()
                for msg in blocks:
                    if not msg:
                        continue
                    try:
                        garbage, msg = msg.rsplit(STX,1)
                        if self.verbose and garbage:
                            print("Some unparsed msg: "+repr(garbage))
                        yield msg
                    except ValueError:
                        if self.verbose:
                            print("No STX found in msg: "+repr(msg))
                        pass

    def receive(self):
        return next(self._reader).decode()

    def sendCmd(self, cmd):
        
        packet = STX + cmd.encode() + ETX

        self.socket.send(packet)
        return self.receive()

    def login(self, pw='F4724744'):
        if pw.isdigit():
            pw = str(pw)
        return self.sendCmd('sMI 0 03 %s' % pw)

    def getInventory(self):
        inv = self.sendCmd('sMN CSGtUID')
        msg = inv.replace('sAN CSGtUID ', '').split(' ')
        nb_tag = msg.pop(0)

        tags = []
        if nb_tag == 0:
            return tags
        
        while len(msg):
            try:
                error = msg.pop(0)
                rssi = msg.pop(0) #Received Signal Strength Indicator
                dsfid = msg.pop(0) #The Data storage format identifier. the implementation of this is up to the creator of the system. its basically a free byte that can be programmed and which is returned during Inventory and Get System Info commands which can tell you something that relates to your system. I have also seen this byte used as a counter or pointer.     
                tag = [msg.pop(0), msg.pop(0), msg.pop(0), msg.pop(0), msg.pop(0), msg.pop(0), msg.pop(0), msg.pop(0)]
                tag_ = [convertToHexString(tag[0]), convertToHexString(tag[1]), convertToHexString(tag[2]), convertToHexString(tag[3]), convertToHexString(tag[4]), convertToHexString(tag[5]), convertToHexString(tag[6]), convertToHexString(tag[7])]
            except Exception as e:
                raise e
            finally:
                tags.append({
                    'serial': ':'.join(tag_).lower(),
                    'tag_original': tag,
                    'error': error,
                    'rssi': rssi,
                    'dsfid': dsfid, 
                    

                })
        logger.debug(pformat(tags, True))
        return tags

    def readInput(self, index=1):
        msg = self.send_command('sMN mDIReadInput %s' % (index) )
        return "sAN mDIReadInput 1" in msg

    def setOutput(self, OutputIndex, OutputValue):
        return self.send_command('sMN mDOSetOutput %s %s' % (OutputIndex, OutputValue))        

    def readTag(self, serial_number):
        serial = ' '.join(serial_number.upper().split(':'))
        msg = self.sendCmd('sMN CSRdMltBlck %s 0 FF' % serial )
        msg = msg.replace('sAN CSRdMltBlck ', '').split(' ')
        
        end_index = None # msg.index("FE") if "FE" in msg else None
        start_index = 2 # msg.index("D4") +1 if "D4" in msg else 2

        hex_payload = " ".join([convertToHexString(x) for x in msg[start_index: end_index]])

        tag = {
            'error': msg[0],
            'leng' : msg[1],
            'index_end': end_index,
            'index_start': start_index,
            'msg': ' '.join(msg[start_index: end_index]),
            'hex_payload' : hex_payload,
            'bytes_payload' : bytes.fromhex(hex_payload),
            'payload': bytes.fromhex(hex_payload) #.decode().replace('\x00', '')
        }
        logger.debug(pformat(tag))
        return tag



    def writeNdefTag(self, serial_number, ndef_message: bytes):
        
        if len(ndef_message) > int('0xff',16):
            raise Exception()

        tag_infos = self.getTagInfo(serial_number)

        magic_word = six.int2byte(0xE1)
        version_and_chmod = six.int2byte(0x40)
        memory_size = six.int2byte(0x28) # TODO COmpute from tag_infos
        support_multiple_read = six.int2byte(0x01)
        
        capability_container= magic_word + version_and_chmod + memory_size + support_multiple_read

        
        type = six.int2byte(0x03)
        length = six.int2byte(len(ndef_message))
        value = ndef_message

        tlv = type+length+value

        tlv_special_end = six.int2byte(0xFE)

        payload = capability_container+tlv+tlv_special_end

        return self.writeTag(serial_number, payload, tag_infos)

    def writeTag(self, serial_number, payload, tag_infos=None):
        
        payload = [hex(x)[2:].upper() for x in payload]

        serial = ' '.join(serial_number.upper().split(':'))

        if not tag_infos:
            tag_infos = self.getTagInfo(serial_number)
        
        nb_bytes = convertToHexString(hex((int(tag_infos['bs'], 16)+1)))
        errors = []
        for i in range(int(tag_infos['nb_blocks'], 16)):

            sub_string = payload[int(i*4):4*i+int(nb_bytes)]
            while len(sub_string) < int(nb_bytes):
                sub_string.append('00')

            start = convertToHexString(hex(i))
            end = convertToHexString(hex(0))
            
            
            cmd = 'sMN WrtMltBlck %s %s %s %s %s' % (serial, start, end, nb_bytes,  ' '.join(sub_string))
            msg = self.sendCmd(cmd)
            if not 'sAN WrtMltBlck 0' in msg:
                errors.append({'=>':cmd, '<=': msg})

        if len(errors) == 0:
            return True
        else:
            logger.error(errors)
            return False




    def selectTag(self, serial_number):
        serial = ' '.join(serial_number.upper().split(':'))
        msg = self.sendCmd('sMN CSSlct %s' % (serial) ) 
        return "sAN CSSlct 0" in msg        

    def setToReady(self, serial_number):
        serial = ' '.join(serial_number.upper().split(':'))
        msg = self.sendCmd('sMN CSRstRdy %s' % (serial) ) 
        return "sAN CSRstRdy 0" in msg      

    def getTagInfo(self, serial_number):
        serial = ' '.join(serial_number.upper().split(':'))
        msg =  self.sendCmd('sMN CSGtTAGInf %s' % (serial) )

        msg = msg.replace('sAN CSGtTAGInf ', '').split(' ')
        tag_info = {
            'error': msg[0],
            'serial': msg[1:9],
            'dsfid_exists' : msg[9],
            'dsfid': msg[10], #The Data storage format identifier. the implementation of this is up to the creator of the system. its basically a free byte that can be programmed and which is returned during Inventory and Get System Info commands which can tell you something that relates to your system. I have also seen this byte used as a counter or pointer.     
            'afi_exists': msg[11],
            'afi': msg[12], # Application Family Identifier
            'nb_block_exists': msg[13],
            'nb_blocks': msg[14], #+1
            'bs_exists': msg[15],
            'bs': msg[16], #+1
            'icr_exist': msg[17],
            'icr': msg[18],
            
        }
        logger.info(tag_info)
        return tag_info        

class RFH630Manager(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.shouldIRun = Event()
        self.shouldIRun.set() 
        self.rf = RFH630(HOST, PORT, verbose=False)
        self.rf.login()
        self.index = 1
        self._data = None

    def run(self):
        while self.shouldIRun.isSet(): 
            samples = self.rf.getInventory()
            self._data = (self.index, samples)
            self.index += 1

    def getScanData(self):
        return self._data

    def requestStop(self):
        self.shouldIRun.clear() 



from math import log
if __name__ == "__main__":
    rf=RFH630(HOST, PORT, verbose=True)

    inv = rf.getInventory()

    import ndef
    content = '0001v3                  TSJTR-19-IT-V31500678.0120221228202112280847020001802022011400819700101                                  Poggio ai Grilli - Chianti'
    
    tube_record = (ndef.TNF_EXTERNAL,   six.b('invineo.com:tube'),  six.b(''), six.b(content)                       ) ##LEN = 174
    
    url_record =  (ndef.TNF_WELL_KNOWN, ndef.RTD_URI,               six.b(''), six.int2byte(4)+six.b('invineo.com/product/002035')   )
    #text_message = ndef.new_message(url_record, tube_record)
    text_message = ndef.new_message(tube_record, url_record)

    payload = text_message.to_buffer()
    

    for tag in inv:
        
        if rf.writeNdefTag(tag['serial'], payload):
            logger.info("Writed successfully")
            logger.info("=============OUTPUT=================")
            content = rf.readTag(tag['serial'])
            logger.info(pformat(content, True))
            logger.info("====================================")
        else:
            logger.error("Could not write tag")
        
            
        


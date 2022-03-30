#!/usr/bin/python
# vim: set fileencoding=utf-8 et sts=4 sw=4:
from __future__ import absolute_import, division, print_function, unicode_literals
from datetime import date, datetime
from threading import Thread, Event, Lock 
import six
"""
  RFID Sick RFH-630
"""

from socket import socket, AF_INET, SOCK_STREAM
from datetime import datetime
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
        self.messages = []

    def __del__( self ):
        self.socket.close()

    def _addMessage(self, type, message):
        self.messages.append({
            "timestamp": datetime.now(),
            'type': type, 
            'message': message
        })

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
        if tags and tags[0]['error'] == 22:
            tags = []
        self._addMessage(logging.INFO, format(tags, True))
        return tags

    def readInput(self, index=1):
        msg = self.sendCmd('sMN mDIReadInput %s' % (index) )
        return "sAN mDIReadInput 1" in msg

    def setOutput(self, OutputIndex, OutputValue):
        self._addMessage(logging.INFO, "Output %s set to %s" %(OutputIndex, OutputValue))
        return self.sendCmd('sMN mDOSetOutput %s %s' % (OutputIndex, OutputValue))        

    def readTag(self, serial_number):
        serial = ' '.join(serial_number.upper().split(':'))
        msg = self.sendCmd('sMN CSRdMltBlck %s 0 FF' % serial )
        msg = msg.replace('sAN CSRdMltBlck ', '').split(' ')
        
        end_index = None # msg.index("FE") if "FE" in msg else None
        start_index = 2 # msg.index("D4") +1 if "D4" in msg else 2

        hex_payload = " ".join([convertToHexString(x) for x in msg[start_index: end_index]])

        tag = {}
        tag.update({'error': msg[0]})
        tag.update({'leng' : msg[1]})
        tag.update({'index_end': end_index})
        tag.update({'index_start': start_index})
        tag.update({'msg': ' '.join(msg[start_index: end_index])})
        tag.update({'hex_payload' : hex_payload})
        tag.update({'bytes_payload' : bytes.fromhex(hex_payload)})
        tag.update({'payload': bytes.fromhex(hex_payload) }) #.decode().replace('\x00', '')


        return tag



    def writeNdefTag(self, serial_number, ndef_message: bytes, check_write=False):
        
        if len(ndef_message) > int('0xff',16):
            raise Exception()

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

        return self.writeTag(serial_number, payload, check_write)

    def writeTag(self, serial_number, payload, check_write=False):
        #payload_len = len(payload)
        payload_hex = [hex(x)[2:].upper() for x in payload]
        written_hex = []
        serial = ' '.join(serial_number.upper().split(':'))

        tag_infos = self.getTagInfo(serial_number)
        if int(tag_infos['error']) > 0 :
            logger.error("Tag infos coul'd not be found. Error n° %s" % tag_infos['error'])
            self._addMessage(logging.ERROR, "Tag infos coul'd not be found. Error n° %s" % tag_infos['error'])
            return False
        
        nb_bytes = convertToHexString(hex((int(tag_infos['bs'], 16)+1)))
        errors = []
        for i in range(int(tag_infos['nb_blocks'], 16)):

            sub_string = payload_hex[int(i*4):4*i+int(nb_bytes)]
            
            while len(sub_string) < int(nb_bytes):
                sub_string.append('00')

            written_hex += sub_string
            start = convertToHexString(hex(i))
            end = convertToHexString(hex(0))
            
            
            cmd = 'sMN WrtMltBlck %s %s %s %s %s' % (serial, start, end, nb_bytes,  ' '.join(sub_string))
            msg = self.sendCmd(cmd)
            if not 'sAN WrtMltBlck 0' in msg:
                errors.append({'=>':cmd, '<=': msg})

        if not check_write:
            if len(errors) == 0:
                return True
            else:
                logger.error(errors)
                self._addMessage(logging.ERROR, errors)
                return False
        else:
            check = self.readTag(serial_number)
            while len(payload) < len(check['bytes_payload']):
                payload += b'\x00'
            #logger.debug("PAYLOAD ORIG : %s" % payload)
            #logger.debug("PAYLOAD CHECK: %s" % check['bytes_payload'])
            #logger.debug("PAYLOAD ORIG : %s" % written_hex)
            #logger.debug("PAYLOAD CHECK: %s" % check['msg'])

            return payload == check['bytes_payload']



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

        tag_info = {}
        try :
        
            tag_info.update({'error': msg[0]})
            tag_info.update({'serial': msg[1:9]})
            tag_info.update({'dsfid_exists' : msg[9]})
            tag_info.update({'dsfid': msg[10]})  #The Data storage format identifier. the implementation of this is up to the creator of the system. its basically a free byte that can be programmed and which is returned during Inventory and Get System Info commands which can tell you something that relates to your system. I have also seen this byte used as a counter or pointer.    
            tag_info.update({'afi_exists': msg[11]})
            tag_info.update({'afi': msg[12]}) # Application Family Identifier
            tag_info.update({'nb_block_exists': msg[13]})
            tag_info.update({'nb_blocks': msg[14]}) #+1
            tag_info.update({'bs_exists': msg[15]})
            tag_info.update({'bs': msg[16]})  #+1
            tag_info.update({'icr_exist': msg[17]})
            tag_info.update({'icr': msg[18]})
        except:
            pass
        
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
        
        if rf.writeNdefTag(tag['serial'], payload, check_write=True):
            logger.info("Writed successfully")
            #logger.info("=============OUTPUT=================")
            #content = rf.readTag(tag['serial'])
            #logger.info(pformat(content, True))
            #logger.info("====================================")
        else:
            logger.error("Could not write tag")
        
            
        


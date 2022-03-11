import ndef

HOST = '192.168.0.100'
PORT = 2111

rf = SickRFH630.RFH630(HOST, PORT)

inv = rf.getInventory()

content = 'My Payload content'
external_record = (ndef.TNF_EXTERNAL,   six.b('baboum.be:tag'),  six.b(''), six.b(content)                       ) ##LEN = 174

url_record =  (ndef.TNF_WELL_KNOWN, ndef.RTD_URI,               six.b(''), six.int2byte(4)+six.b('baboum.be')   )

text_message = ndef.new_message(external_record, url_record)

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
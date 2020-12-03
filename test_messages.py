
# Stop linting errors
#pylint: disable=C0301,C0111,W0212,C0413,C0103,W0703
import binascii
import os

# estreamer imports (after paths etc)
import estreamer.adapters.base64
import estreamer.adapters.binary
import estreamer.crossprocesslogging as logging
import estreamer.definitions as definitions
import estreamer.message
import estreamer.pipeline
import estreamer.streams


FILELOG_MALWARE_MESSAGE = {
    'source': '1',
    'length': 434,
    'version': 1,
    'data': binascii.unhexlify(
        '000001f6000001a258ae28850000000000000038000001a200000002001c4bc358adfb4758adfb6600000000000000000000ffff05fffa1600000000000000000000ffff0a20011202040b13000000060611b40bf45bc617b7e31c493ec6ffa53d6ef38ddbe82062dadfafaff3dffc0100000009000000000000003542616e6b2d576972652d5472616e736665722de794b5e6b187e8afb4e6988e2d31303031323031352e70646600000000000000a3c601000002a40098967f0000000000000092687474703a2f2f7777772e6365646172732d73696e61692e6564752f496e7465726e6174696f6e616c2d50617469656e74732f4368696e6573652f446f63756d656e74732f42616e6b2d576972652d5472616e736665722d2545372539342542352545362542312538372545382541462542342545362539382538452d31303031323031352e706466000000000000000008a799005006173e48688ffa11e69c288816deb0aacf0348000000000000000008a3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000800000000c8'
    ),
    'messageType': 4
}

ERROR_MESSAGE_GOOD = {
    'length': 15,
    'version': 1,
    'data': binascii.unhexlify('0000001300094e6f20737061636500'),
    'messageType': 1
}

ERROR_MESSAGE_BAD = {
    'length': 15,
    'version': 1,
    'data': binascii.unhexlify('00000013000a4e6f20737061636500'),
    'messageType': 1
}


def test_parse_ERROR_MESSAGE():
    record = estreamer.adapters.binary.loads( ERROR_MESSAGE_GOOD )
    assert record['code'] == 19
    assert record['text'] == 'No space'



def test_parse_ERROR_MESSAGE_BAD():
    try:
        estreamer.adapters.binary.loads( ERROR_MESSAGE_BAD )
        assert False

    except estreamer.ParsingException:
        assert True



def test_create_ERROR_MESSAGE():
    msg = estreamer.message.ErrorMessage('hello')
    binary = msg.getWireData()
    msg = estreamer.message.parse( binary )
    record = estreamer.adapters.binary.loads( msg )
    assert record['code'] == -1
    assert record['text'] == 'hello'



def test_parse_FILELOG_MALWARE():
    record = estreamer.adapters.binary.loads( FILELOG_MALWARE_MESSAGE )

    assert record['recordType'] == definitions.RECORD_FILELOG_MALWARE_EVENT
    assert record['fileEventTimestamp'] == 1487797094
    assert record['uri']['data'] == u'http://www.cedars-sinai.edu/International-Patients/Chinese/Documents/Bank-Wire-Transfer-%E7%94%B5%E6%B1%87%E8%AF%B4%E6%98%8E-10012015.pdf\x00'.replace('\0', '')
    assert record['fileName']['data'] == u'Bank-Wire-Transfer-\u7535\u6c47\u8bf4\u660e-10012015.pdf\x00'.replace('\0', '')
    assert record['accessControlPolicyUuid'] == '173e4868-8ffa-11e6-9c28-8816deb0aacf'



def test_outputter_FILELOG_MALWARE( settings ):
    estreamer.pipeline.parseDecorateTransformWrite( FILELOG_MALWARE_MESSAGE, settings )
    settings.close()
    #cleanup( settings )



def test_parse_PACKET():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTQ3MwpzUyd2ZXJzaW9uJwpwMgpJMQpzUydkYXRhJwpwMwpTJ1x4MDBceDAwXHgwMFx4MDJceDAwXHgwMFx4MDFceGM5WHhceGUzXHhjY1x4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAxXHgwMFx4MDJceGNjXHhlNFh4XHhlM1x4YzlYeFx4ZTNceGM5XHgwMFx4MDFceDljXHg5M1x4MDBceDAwXHgwMFx4MDFceDAwXHgwMFx4MDFceGFkXHgwMFBaXHhmYVx4Y2VceDAxXHgwMlx4MWFceGM1XHgwMlx4MDBceDAwXHgwOFx4MDBFXHgwMFx4MDFceDlifXhceDAwXHgwMFx4ZmZceDA2W1xuXG5ceDhkXG4iXHgxNFx4MDJceGI5KWcgXHgwMFx4MTVceGE1XHhiNVx4ODNiblx4YmVuXHg5Y1BceDEwP1x4ZmY7XHgxZVx4MDBceDAwTElTVCAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipceGZmXHgwY1x4YzBRJwpwNApzUydtZXNzYWdlVHlwZScKcDUKSTQKcy4='
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['recordType'] == definitions.RECORD_PACKET
    assert record['packetData'] == '00505aface01021ac502000008004500019b7d780000ff065b0a0a8d0a221402b92967200015a5b583626ebe6e9c50103fff3b1e00004c495354202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2aff0cc051'
    assert record['eventSecond'] == 1484317641



def test_parse_SENSOR():
    b64 = u'KGRwMApTJ3NvdXJjZScKcDEKUycxJwpwMgpzUydsZW5ndGgnCnAzCkkyNQpzUyd2ZXJzaW9uJwpwNApJMQpzUydkYXRhJwpwNQpTJ1x4MDBceDAwXHgwMHtceDAwXHgwMFx4MDBceDExXHgwMFx4MDBceDAwXHgwMVx4MDBceDAwXHgwMFx0U2Vuc29yMTg4JwpwNgpzUydtZXNzYWdlVHlwZScKcDcKSTQKcy4='
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['name'] == 'Sensor188'



def test_parse_DNS_RECORD():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTUzCnNTJ3ZlcnNpb24nCnAyCkkxCnNTJ2RhdGEnCnAzClMnXHgwMFx4MDBceDAxQFx4MDBceDAwXHgwMC1ceDAwXHgwMFx4MDA9XHgwMFx4MDBceDAwLVx4MDBceDAwXHgwMFx4MDFceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXG5BXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDE3YSBob3N0IGFkZHJlc3NceDAwJwpwNApzUydtZXNzYWdlVHlwZScKcDUKSTQKcy4='
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['description']['data'] == 'a host address'



def test_parse_DNS_RESPONSE():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTc3CnNTJ3ZlcnNpb24nCnAyCkkxCnNTJ2RhdGEnCnAzClMnXHgwMFx4MDBceDAxQVx4MDBceDAwXHgwMEVceDAwXHgwMFx4MDA9XHgwMFx4MDBceDAwRVx4MDBceDAwXHgwZlx4MDJceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgxMVNJTktIT0xFXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDAoU2lua2hvbGUgcmVzcG9uc2UgZnJvbSBmaXJld2FsbFx4MDAnCnA0CnNTJ21lc3NhZ2VUeXBlJwpwNQpJNApzLg=='
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['description']['data'] == 'Sinkhole response from firewall'



def test_parse_SINKHOLE():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTU3CnNTJ3ZlcnNpb24nCnAyCkkxCnNTJ2RhdGEnCnAzClMnXHgwMFx4MDBceDAxQlx4MDBceDAwXHgwMDFceDAwXHgwMFx4MDBceDBlXHgwMFx4MDBceDAwMSJcXFx4OTAgPVx4OTJceDExXHhlNlx4YTJceGI4UTlceDE1XHhjNlx4ODQwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MTlNYWx3YXJlX1Npbmtob2xlXHgwMCcKcDQKc1MnbWVzc2FnZVR5cGUnCnA1Ckk0CnMu'
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['name']['data'] == 'Malware_Sinkhole'



def test_RNA_FINGERPRINT():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTcxCnNTJ3ZlcnNpb24nCnAyCkkxCnNTJ2RhdGEnCnAzClMnXHgwMFx4MDBceDAwNlx4MDBceDAwXHgwMD9cXFx4ZTRcclx4OWNNXHhjOEE9XHg5NFx4ZWRceDgyXHhhOFx4YzZceGExSF9ceDAwXHgwMFx4MDBceDFlQ2lzY28gMTEzMSBTZXJpZXMgQWNjZXNzIFBvaW50XHgwMFx4MDBceDAwXHgwNUNpc2NvXHgwMFx4MDBceDAwXHgwMCcKcDQKc1MnbWVzc2FnZVR5cGUnCnA1Ckk0CnMu'
    message = estreamer.adapters.base64.loads( b64 )
    record = estreamer.adapters.binary.loads( message )

    assert record['version'] == ''



def test_wire_Null():
    msg = estreamer.message.NullMessage()
    binary = msg.getWireData()
    hexy = binascii.hexlify( binary )
    assert hexy == '0001000000000000'



def test_RECORD_RUA_USER_BadOffset():
    b64 = u'KGRwMApTJ2xlbmd0aCcKcDEKSTMzCnNTJ3ZlcnNpb24nCnAyCkkxCnNTJ2RhdGEnCnAzClMnXHgwMFx4MDBceDAwYlx4MDBceDAwXHgwMFx4MTlceDAwXHgwMEFVXHgwMFx4MDBceDAyXHhjNlx4MDBceDAwXHgwMFxyYWRtaW5pc3RyYXRvcicKcDQKc1MnbWVzc2FnZVR5cGUnCnA1Ckk0CnMu'
    message = estreamer.adapters.base64.loads( b64 )

    # This is a bad message. Kept for posterity. It will throw a parsing error
    try:
        estreamer.adapters.binary.loads( message )
        assert 0

    except estreamer.ParsingException:
        assert 1


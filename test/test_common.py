import uuid
import estreamer.common.convert as convert
from estreamer.common import Packet

def test_common_convert_infer():
    assert convert.infer( "NULL" ) is None
    assert convert.infer( "1" ) == 1
    assert convert.infer( "1.1" ) == 1.1
    assert convert.infer( "abc" ) == "abc"

    uuid1 = uuid.uuid1()
    assert convert.infer( str(uuid1) ) == uuid1

    assert convert.infer( "True" )



def test_common_istype():
    assert convert.isInt( "34" )
    assert not convert.isInt( "Banana" )
    assert convert.isUint16( "0" )
    assert convert.isUint16( "22222" )
    assert convert.isUint16( "65535" )
    assert not convert.isUint16( "65536" )
    assert not convert.isUint16( "-1" )
    assert not convert.isUint16( "Banana" )



def test_Packet():
    hexDataTcp = ( "00505aface01021ac50200000800"
                  "4500019b7d780000ff065b0a0a8d0a221402b929"
                  "67200015a5b583626ebe6e9c50103fff3b1e0000"
                  "4142434445464748494a" )
    hexDataUdp = ( "004268f4ae3cc85b76bc58190800"
                  "450000437ad5000080110c5e0a7661a4406606f7"
                  "c4000035002f9c24"
                  "4142434445464748494a" )
    packetTcp = Packet.createFromHex( hexDataTcp )
    packetUdp = Packet.createFromHex( hexDataUdp )
    assert packetTcp.getPayloadAsHex() == "4142434445464748494a"
    assert packetUdp.getPayloadAsHex() == "4142434445464748494a"
    assert packetTcp.getPayloadAsAscii() == "ABCDEFGHIJ"
    assert packetUdp.getPayloadAsAscii() == "ABCDEFGHIJ"
    assert packetTcp.getPayloadAsUtf8() == u"ABCDEFGHIJ"
    assert packetUdp.getPayloadAsUtf8() == u"ABCDEFGHIJ"

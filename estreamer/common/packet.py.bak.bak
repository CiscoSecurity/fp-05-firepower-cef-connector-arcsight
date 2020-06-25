
#********************************************************************
#      File:    packet.py
#      Author:  Richard Clendenning
#
#      Description:
#       Packet helper class
#
#      Copyright (c) 2018 by Cisco Systems, Inc.
#
#       ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
#       OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
#       INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
#       PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
#       CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.
#
#*********************************************************************/
import binascii
import struct

class Packet( object ):
    """
    Helper class for binary packet data
    """
    LAYER2_HEADER_LENGTH = 14
    TCP_PROTOCOL = '\x06'
    UDP_PROTOCOL = '\x11'
    IP_PROTOCOL_OFFSET = 9
    IP_HEADER_LENGTH_NYBLE = 1
    TCP_HEADER_LENGTH_NYBLE = 24
    UDP_HEADER_LENGTH = 8
    WORDS_TO_BYTES_FACTOR = 4

    def __init__( self, data ):
        self.data = data
        self.layer3HeaderLength = 0

    def __getNyble( self, indexNyble ):
        byteIndex = indexNyble/2
        byte = struct.unpack( '>B', self.data[byteIndex] )[0]
        if indexNyble % 2 == 0:
            mask = 0b11110000
            return ( byte & mask ) >> 4
        mask = 0b00001111
        return byte & mask

    def __getLayer3HeaderLength( self ):
        if self.layer3HeaderLength == 0:
            ipOffsetNyble = (
                Packet.LAYER2_HEADER_LENGTH * 2 +
                Packet.IP_HEADER_LENGTH_NYBLE )

            self.layer3HeaderLength = (
                self.__getNyble( ipOffsetNyble ) *
                Packet.WORDS_TO_BYTES_FACTOR )

        return self.layer3HeaderLength

    def __getLayer4HeaderLength( self ):
        ipProtocolOffset = (
            Packet.LAYER2_HEADER_LENGTH +
            Packet.IP_PROTOCOL_OFFSET )

        protocol = self.data[ ipProtocolOffset: ipProtocolOffset + 1 ]

        if protocol == Packet.UDP_PROTOCOL:
            return Packet.UDP_HEADER_LENGTH

        elif protocol == Packet.TCP_PROTOCOL:
            tcpOffsetNyble = (
                Packet.LAYER2_HEADER_LENGTH * 2 +
                self.__getLayer3HeaderLength() * 2 +
                Packet.TCP_HEADER_LENGTH_NYBLE )

            return (
                self.__getNyble( tcpOffsetNyble ) *
                Packet.WORDS_TO_BYTES_FACTOR )

        return 0

    def getPayloadAsBytes( self ):
        headerLengthSum = (
            Packet.LAYER2_HEADER_LENGTH +
            self.__getLayer3HeaderLength() +
            self.__getLayer4HeaderLength() )

        return self.data[headerLengthSum:]

    def getPayloadAsHex( self ):
        hexPayload = binascii.hexlify( self.getPayloadAsBytes() )
        return hexPayload

    def getPayloadAsAscii( self ):
        asciiPayload = self.getPayloadAsBytes().decode( 'ascii', 'ignore' )
        return asciiPayload

    def getPayloadAsUtf8( self ):
        utf8Payload = self.getPayloadAsBytes().decode( 'utf-8', 'ignore' )
        return utf8Payload

    @staticmethod
    def createFromHex( data ):
        binData = binascii.unhexlify( data )
        return Packet( binData )
        
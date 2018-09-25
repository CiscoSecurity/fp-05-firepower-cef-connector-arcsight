
#********************************************************************
#      File:    binary.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Handles binary parsing of message and record data
#
#      Copyright (c) 2017 by Cisco Systems, Inc.
#
#       ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
#       OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
#       INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
#       PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
#       CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.
#
#*********************************************************************/
import binascii
import os
import pickle
import socket
import struct
import uuid

#pylint: disable=E1101,W0612,C0413
if os.name == 'nt':
    import win_inet_pton

import estreamer.definitions as definitions
import estreamer.crossprocesslogging as logging
from estreamer import ParsingException

from estreamer.definitions import TYPE_BYTE
from estreamer.definitions import TYPE_UINT16
from estreamer.definitions import TYPE_UINT32
from estreamer.definitions import TYPE_UINT64
from estreamer.definitions import TYPE_UINT128
from estreamer.definitions import TYPE_UINT160
from estreamer.definitions import TYPE_UINT256
from estreamer.definitions import TYPE_VARIABLE
from estreamer.definitions import TYPE_UUID
from estreamer.definitions import TYPE_IPV4
from estreamer.definitions import TYPE_IPV6
from estreamer.definitions import TYPE_MAC
from estreamer.definitions import RECORDS
from estreamer.definitions import BLOCK_AUTO
from estreamer.definitions import BLOCK_SERIES_2_SHIM
from estreamer.definitions import BLOCKS_SERIES_1
from estreamer.definitions import BLOCKS_SERIES_2


class Binary( object ):
    """
    The Binary class deserializes raw estreamer wire messages into a native
    structured dictionary
    """
    def __init__( self, source ):
        self.source = source
        self.logger = logging.getLogger( __name__ )
        self.data = None
        self.length = 0
        self.recordType = 0
        self.offset = 0
        self.record = None
        self.isParsed = False

        self.inetNtop = socket.inet_ntop
        if os.name == 'nt':
            self.inetNtop = win_inet_pton.inet_ntop

        # Do not touch source. Leave it alone.
        if 'data' not in source:
            self.logger.info('loads(): data not in response')
            self.logger.info( source )

        else:
            self.data = source['data']

        if source['messageType'] == definitions.MESSAGE_TYPE_EVENT_DATA:
            self._eventHeader( self.data )

        elif source['messageType'] == definitions.MESSAGE_TYPE_ERROR:
            self._errorMessage( source )

        else:
            raise ParsingException(
                'Unexpected message type: {0}'.format( source['messageType']))



    # Function pointers
    unpackDiscovery = struct.Struct('>LLBBBBBBBBLLLLLL').unpack
    unpackUint32 = struct.Struct('>L').unpack
    unpackMac = struct.Struct('>BBBBBB').unpack



    @staticmethod
    def _formatMacAddress( *byteArray ):
        return ':'.join( format( byte, '02x' ) for byte in byteArray)



    @staticmethod
    def getImpact( bits ):
        """Returns a simple integer impact value from a bitfield"""
        impact = 0 # Default to unknown impact

        # Compare bits to the corresponding masks
        if bits & 0b11011000:
            impact = 1

        elif (bits & 0b00000110) == 0b00000110:
            impact = 2

        elif bits & 0b00000010:
            impact = 3

        elif bits & 0b00000001:
            impact = 4

        # Return the resulting impact score
        return impact



    def _ip2str( self, addressFamily, packedIp ):
        ipAddress = self.inetNtop( addressFamily, packedIp )

        if ipAddress.startswith('::ffff:'):
            return ipAddress[7:]

        return ipAddress



    def _parseDiscoveryHeader( self, data, offset, record ):

        (deviceId, legacyIpAddress, mac1, mac2, mac3, mac4, mac5, mac6,
         hasIpv6, ignore1, eventSecond, eventMicrosecond, eventType,
         eventSubtype, ignore2, ignore3 ) = Binary.unpackDiscovery(
             data[ offset : offset + ( 4 * 10 ) ] )

        record[ 'deviceId' ] = deviceId
        record[ 'legacyIpAddress' ] = self._ip2str(
            socket.AF_INET,
            data[ offset + 4 : offset + 8])

        record[ 'macAddress' ] = Binary._formatMacAddress(
            mac1, mac2, mac3, mac4, mac5, mac6 )

        record[ 'hasIpv6' ] = hasIpv6
        record[ 'eventSecond' ] = eventSecond
        record[ 'eventMicrosecond' ] = eventMicrosecond
        record[ 'eventType' ] = eventType
        record[ 'eventSubtype' ] = eventSubtype

        offset += 40

        if hasIpv6 == 1:
            ipv6 = self._ip2str( socket.AF_INET6, data[40:56] )
            record[ 'ipv6Address' ] = ipv6
            offset += 16

        return offset



    @staticmethod
    def _blockDefinition( key ):
        if key is None:
            raise ParsingException('Unknown block definition: {0}', key )

        if not key & BLOCK_SERIES_2_SHIM:
            if key not in BLOCKS_SERIES_1:
                raise ParsingException('Unknown block definition: {0}', key )

            else:
                return BLOCKS_SERIES_1[ key ]

        else:
            if key not in BLOCKS_SERIES_2:
                raise ParsingException('Unknown block definition: {0}', key )

            else:
                return BLOCKS_SERIES_2[ key ]



    def _parseBlock( self, data, offset, attribute, context ):

        blockKey = None

        if 'block' in attribute:
            if attribute['block'] == BLOCK_AUTO:
                ( blockKey, ) = Binary.unpackUint32( data[ offset : ( offset + 4 ) ] )

            elif isinstance( attribute['block'], int ):
                blockKey = attribute['block']

        elif 'list' in attribute:
            if attribute['list'] == BLOCK_AUTO:
                ( blockKey, ) = Binary.unpackUint32( data[ offset : ( offset + 4 ) ] )

            elif isinstance( attribute['list'], int ):
                blockKey = attribute['list']


        blockDefinition = Binary._blockDefinition( blockKey )
        offset = self._parseAttributes( data, offset, blockDefinition, context )
        return offset



    def _parseVariable( self, data, offset, attribute, context ):
        lengthSource = attribute[ 'length' ]
        blockLength = context[ lengthSource ]
        attributeName = attribute[ 'name' ]

        if 'adjustment' in attribute:
            lengthAdjustment = attribute[ 'adjustment' ]

        else:
            lengthAdjustment = 0

        length = blockLength + lengthAdjustment

        if length > 0:
            value = data[ offset : ( offset + length ) ]

            try:
                # Most of the time value will be a string which means it will be UTF8
                value = value.decode('utf-8')

                # Since here, remove nulls
                context[ attributeName ] = value.replace('\0', '')

            except UnicodeDecodeError:
                # But sometimes we have blobs or just "variable" data as in a packet
                context[ attributeName ] = binascii.hexlify( value )

            offset += length

        elif length == 0:
            context[ attributeName ] = ''

        else:
            raise ParsingException(
                'Invalid block length ({0}). RecordType={1}, Field={2}'.format(
                    blockLength,
                    self.recordType,
                    attribute['name'] ))

        return offset



    def _parseAttributes( self, data, offset, attributes, context ):
        recordType = self.recordType
        recordLength = len( data )

        for attribute in attributes:
            attributeName = attribute[ 'name' ] if 'name' in attribute else None

            if self.logger.isEnabledFor( logging.TRACE ):
                self.logger.log(
                    logging.TRACE,
                    'offset={0}/{1} | attribute={2}'.format(
                        offset,
                        recordLength,
                        attribute ))

            if offset > recordLength:
                raise ParsingException(
                    '_attributes() | offset ({0}) > length ({1}) | recordType={2}'.format(
                        offset,
                        recordLength,
                        recordType ))

            elif offset == recordLength:
                if 'type' in attribute and attribute['type'] == TYPE_VARIABLE:
                    context[ attributeName ] = ''

                return offset

            if 'discovery' in attribute:
                offset = self._parseDiscoveryHeader( data, offset, context )

            elif 'type' in attribute:
                attributeType = attribute[ 'type' ]

                if attributeType == TYPE_UUID:
                    byteLength = 16
                    guid = uuid.UUID( bytes = data[ offset : offset + byteLength ] )
                    context[ attributeName ] = str(guid)
                    offset += byteLength

                elif attributeType == TYPE_IPV6:
                    byteLength = 16
                    context[ attributeName ] = self._ip2str(
                        socket.AF_INET6,
                        data[ offset : offset + byteLength ] )

                    offset += byteLength

                elif attributeType == TYPE_IPV4:
                    byteLength = 4
                    context[ attributeName ] = self._ip2str(
                        socket.AF_INET,
                        data[ offset : offset + byteLength ] )

                    offset += byteLength

                elif attributeType == TYPE_MAC:
                    byteLength = 6
                    macX = Binary.unpackMac(
                        data[ offset : offset + byteLength ] )

                    context[ attributeName ] = Binary._formatMacAddress( *macX )
                    offset += byteLength

                elif attributeType == TYPE_VARIABLE:
                    offset = self._parseVariable( data, offset, attribute, context )

                elif attributeType == TYPE_UINT128 or \
                    attributeType == TYPE_UINT160 or \
                    attributeType == TYPE_UINT256:

                    byteLength = len( attributeType )

                    #Unpack as network big-endian
                    value = struct.unpack(
                        '>' + attributeType,
                        data[ offset : offset + byteLength ])

                    # repack native. This step is probably not necessary as
                    # endianness should only apply to bytes, not bits and we're
                    # pulling out raw groups of bytes. TODO
                    value = struct.pack( attributeType, *value )

                    context[ attributeName ] = binascii.hexlify( value )
                    offset += byteLength

                else:
                    if attributeType == TYPE_BYTE:
                        byteLength = 1

                    elif attributeType == TYPE_UINT16:
                        byteLength = 2

                    elif attributeType == TYPE_UINT32:
                        byteLength = 4

                    elif attributeType == TYPE_UINT64:
                        byteLength = 8

                    else:
                        raise ParsingException( 'Unknown type: {0}'.format( attributeType ) )

                    context[ attributeName ] = struct.unpack(
                        '>' + attributeType,
                        data[ offset : offset + byteLength ] )[ 0 ]

                    offset += byteLength

            elif 'list' in attribute:
                oldOffset = offset

                ( listType, listLength ) = struct.unpack(
                    '>LL',
                    data[  offset : ( offset + 8 ) ] )

                offset += 8

                container = {
                    'listType': listType,
                    'listLength': listLength,
                    'items': []
                }

                while ( offset - oldOffset ) < listLength:
                    block = {}
                    offset = self._parseBlock( data, offset, attribute, block )
                    container[ 'items' ].append( block )

                context[ attributeName ] = container

            elif 'block' in attribute:
                block = context
                if attributeName is not None:
                    context[ attributeName ] = {}
                    block = context[ attributeName ]

                offset = self._parseBlock( data, offset, attribute, block )

        return offset



    def _parse( self, data, offset, record ):
        recordType = record[ 'recordType' ]
        recordLength = len( data )
        try:
            #if recordType == 95:
            attributes = RECORDS[ recordType ][ 'attributes' ]
            offset = self._parseAttributes( data, offset, attributes, record )

        except (AttributeError, ValueError) as ex:
            hexRecord = binascii.hexlify( data )
            self.logger.error( 'AttributeError: Record={0}'.format( hexRecord ) )
            self.logger.exception(ex)
            return

        if offset != recordLength:
            msg = '__parse(): Offset ({0}) != recordLength ({1}) for recordType {2}'.format(
                offset,
                recordLength,
                recordType)

            if offset < recordLength:
                self.logger.warning( msg )

            else:
                raise ParsingException( msg )



    def _eventHeader( self, data ):
        ( recordType, recordLength ) = struct.unpack( '>LL', data[0:8] )

        self.recordType = recordType

        offset = 0
        record = {
            'recordType': recordType,
            'recordLength': recordLength
        }

        if len( data ) == ( 8 + recordLength ):
            record[ 'archiveTimestamp' ] = 0
            record[ 'checksum' ] = 0
            offset = 8
            #record[ 'record' ] = data[ 8 : 8 + recordLength ]

        elif len( data ) == ( 16 + recordLength ):
            ( archiveTimestamp, checksum ) = struct.unpack( '>LL', data[ 8:16 ] )
            record[ 'archiveTimestamp' ] = archiveTimestamp
            record[ 'checksum' ] = checksum
            offset = 16
            #record[ 'record' ] = data[ 16 : 16 + recordLength ]

        else:
            raise ParsingException('Invalid length')

        self.offset = offset
        self.record = record



    def _errorMessage( self, source ):
        ( errorCode, length ) = struct.unpack( '>lH', source['data'][0:6] )
        offset = 6

        expectedLength = offset + length
        actualLength = len( source['data'] )

        if expectedLength != actualLength:
            raise ParsingException(
                'Expected error message length is {0} but actual is {1}'.format(
                    expectedLength,
                    actualLength ))


        value = source[ 'data' ][ offset : ( offset + length ) ]

        try:
            # Most of the time value will be a string which means it will be UTF8
            value = value.decode('utf-8')

            # Since here, remove nulls
            value = value.replace('\0', '')

        except UnicodeDecodeError:
            # If this is happening here then something seriously bad is going on
            value = binascii.hexlify( value )

        self.record = {
            'code': errorCode,
            'text': value
        }

        self.offset = actualLength
        self.isParsed = True



    def parse( self ):
        """
        This is the core of this project. Takes a binary message from
        eStreamer and loads it into a common dict format which is used
        everywhere else
        """
        if not self.isParsed:
            if self.recordType not in RECORDS:
                self.logger.warning( '__decode(): Unknown record type {0}.'.format(
                    self.recordType ))
                return

            if self.logger.isEnabledFor( logging.TRACE ):
                self.logger.log( logging.TRACE, binascii.hexlify( self.data ) )

            self._parse( self.data, self.offset, self.record )
            self.isParsed = True





def loads( source ):
    """
    Converts an incoming raw binary response into native structured
    dictionary
    """
    parser = Binary( source )
    parser.parse()
    return parser.record



def dumps( source ):
    """Returns the source parameter as bytes"""
    # data should already be bytes. But if not...
    if isinstance( source, dict ):
        return pickle.dumps( source )

    # do nothing
    return source

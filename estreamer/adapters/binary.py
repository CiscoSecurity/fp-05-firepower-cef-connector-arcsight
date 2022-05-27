
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
from __future__ import absolute_import
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
from estreamer.definitions import TYPE_UINT8
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
        self.blockType = 0
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

        recordLength = len( data )
        recordType =  record[ 'recordType' ]
        blockType = record[ 'blockType' ]
        record[ 'deviceId' ] = deviceId

        headerLength = int( record[ 'recordLength' ] )
       
        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log( logging.TRACE, "data value for host ip in bytes")

        record[ 'hostIpAddr'] = self._ip2str( socket.AF_INET6, data[56:72] )

        if self.logger.isEnabledFor( logging.TRACE ):

            self.logger.log( logging.TRACE, "rec type :-:{0}, block type:={1} ip host: {2}".format(recordType, eventSubtype, record[ 'hostIpAddr' ]) )

        record[ 'macAddress' ] = Binary._formatMacAddress(
            mac1, mac2, mac3, mac4, mac5, mac6 )

        record[ 'eventSecond' ] = eventSecond
        record[ 'eventMicrosecond' ] = eventMicrosecond
        record[ 'eventType' ] = eventType
        record[ 'eventSubtype' ] = eventSubtype
        offset += 40

        if hasIpv6 == 1:
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

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log(logging.TRACE, '_parseBlock: recordType: {0} blockKey: {1} '.format(self.recordType, blockKey))

        if blockKey != 0 :
            self.blockType = blockKey

        blockDefinition = Binary._blockDefinition( blockKey )
        offset = self._parseAttributes( data, offset, blockDefinition, context )
        return offset



    def _parseVariable( self, data, offset, attribute, context ):

        lengthSource = attribute[ 'length' ]
        blockLength = context[ lengthSource ]

        if self.logger.isEnabledFor( logging.TRACE ):
           binhex = data[offset:blockLength]
           self.logger.log(
              logging.TRACE,
              'offset= {0}/{1} |  attribute={1} | context={2} | data[{0}:{1}]={3}'.format(
                 offset, blockLength,
                 attribute,
                 context, binhex ))

        attributeName = attribute[ 'name' ]

        if 'adjustment' in attribute:
            lengthAdjustment = attribute[ 'adjustment' ]

            if self.logger.isEnabledFor( logging.TRACE ):
               binhex = data[offset:( offset + 8 ) ]
               self.logger.log(
                  logging.TRACE,
                  'length adjustment= {0} | block size={1} | attribute={2} | blockLength={3}'.format(
                     lengthAdjustment, binhex,
                     attribute,blockLength))
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
            value = data[ offset : ( offset + length ) ]
            raise ParsingException(
                'Invalid block length ({0}) length2: {1} at pos {7}. RecordType={2}, BlockType={3}, Field={4} Length={5} Value={6}'.format(
                    blockLength,
                    length,
                    self.recordType,
                    self.blockType,
                    attribute['name'] ,
                    attribute['length'],
                    value,
                    offset))

        return offset



    def _parseAttributes( self, data, offset, attributes, context ):
        recordType = self.recordType
        blockType = self.blockType
        recordLength = len( data )

        for attribute in attributes:
            attributeName = attribute[ 'name' ] if 'name' in attribute else None

            if self.logger.isEnabledFor( logging.TRACE ):
                binhex = data[offset:recordLength]
                self.logger.log(
                    logging.TRACE,
                    'offset={0}/{1} | attribute={2} | data[{0}:{1}]={3}'.format(
                        offset,
                        recordLength,
                        attribute, binhex ))

            if offset > recordLength:
                raise ParsingException(
                    '_attributes() | offset ({0}) > length ({1}) | blockType={2} recordType={3}'.format(
                        offset,
                        recordLength,
                        blockType,
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
                    if self.logger.isEnabledFor( logging.TRACE ):
                        self.logger.log(
                        logging.TRACE,
                        'attributeVariable: data={0} | offset={1} | attribute={2} | context={3}'.format(
                            data,
                            offset, attribute, context ))

                    offset = self._parseVariable( data, offset, attribute, context )

                elif attributeType == TYPE_UINT128 or \
                    attributeType == TYPE_UINT160 or \
                    attributeType == TYPE_UINT256:

                    byteLength = len( attributeType )

                    #Unpack as network big-endian
                    value = struct.unpack(
                        '>' + attributeType,
                        data[ offset : offset + byteLength ])

                    if self.logger.isEnabledFor( logging.TRACE ):
                        self.logger.log(
                        logging.TRACE,
                        'offset={0}/{1} | attribute={2} | value={3} | data={4}'.format(
                            offset,
                            byteLength,
                            attribute, value, data[offset : offset + byteLength] ))

                    # repack native. This step is probably not necessary as
                    # endianness should only apply to bytes, not bits and we're
                    # pulling out raw groups of bytes. TODO
                    value = struct.pack( attributeType, *value )

                    context[ attributeName ] = binascii.hexlify( value )
                    offset += byteLength

                else:
                    if attributeType == TYPE_BYTE:
                        byteLength = 1
                        
                    elif attributeType == TYPE_UINT8:
                        byteLength = 1
                        
                    elif attributeType == TYPE_UINT16:
                        byteLength = 2

                    elif attributeType == TYPE_UINT32:
                        byteLength = 4

                    elif attributeType == TYPE_UINT64:
                        byteLength = 8

                    else:
                        raise ParsingException( 'Unknown type: {0}'.format( attributeType ) )
                   

                    if recordType == 98 :
                        maxLen = len(data)

                        context['id'] = struct.unpack('>'+TYPE_UINT32, data[16:20])[0]
                        context['protocol'] = struct.unpack('>'+TYPE_UINT32, data[20:24])[0]

                        #24-28  Type always 0
                        recLenBytes = struct.unpack('>'+TYPE_UINT32, data[28:32])[0]
                        nameLength = int( recLenBytes - 8 )  # 24 - 8
                        maxLength = int(nameLength + 32)
                        name = struct.unpack('>'+str(nameLength)+'s',data[32: maxLength])[0]
                        self.logger.log ( logging.TRACE, 'username(len): {0}|size: {1}|data: {1}'.format (recLenBytes, nameLength, data[32: maxLength])  )

                        context['username'] = name.decode('utf-8')
                        if (len(name) > 0 ) :
                            username = str(context['username'])
                            context['username'] = username.rstrip(username[-1])

                        self.logger.log( logging.TRACE, 'username : {0}'.format(name) )
                        offset = maxLength

                    else:     
                        try:
                            self.logger.log( logging.TRACE, 'unpacking binary data {0}'.format(attributeName) )
                            context[ attributeName ] = struct.unpack(
                                 '>' + attributeType, data[ offset : offset + byteLength ] )[ 0 ]
                            offset += byteLength

                        except struct.error:
                            hData = binascii.hexlify( data[ offset: offset + byteLength ] )
                            hexData = binascii.hexlify( data )

                            raise ParsingException('Error Decoding binary for rec_type={0} attr={1} type={2} data={3} data_full={4}'.format( recordType, attributeName, attributeType, hData, hexData ) )


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

                self.logger.log( logging.TRACE, 'Parsing Attribute (Block Type) :-: attr name={0}:attr={1}:attr_type={2}:value={3}'.format(attributeName, attribute, block, offset) )
                offset = self._parseBlock( data, offset, attribute, block )

        return offset



    def _parse( self, data, offset, record ):
        recordType = record[ 'recordType' ]
        blockType = self.blockType
        recordLength = len( data )

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log(
                logging.TRACE,
                '_parse offset={0}/{1} | recordType={2}  '.format(
                    offset,
                    recordLength, recordType))
        try:
            attributes = RECORDS[ recordType ][ 'attributes' ]

            #Dynamic according to blocktype
            if recordType == 71 or recordType == 210:
                blockSubType = struct.unpack(
                                '>' + TYPE_UINT32,
                                data[ 72 : 76 ] )[ 0 ]

                self.logger.log(logging.TRACE, 'parsing start {0} offset: {1} parsing: {2}'.format(data, offset, data[72:76]))
                self.logger.log(logging.TRACE, 'parsing blockType {0}'.format(blockSubType))
                self.logger.log(logging.TRACE, 'parsing recordTypeType {0}'.format(recordType))

                if blockSubType == 160 :
                    attributes = RECORDS[  1060 ]['attributes']

                    self.logger.log(logging.TRACE, 'IPS BLOCK {0} attributes={1}'.format(blockType, attributes))

                elif blockSubType == 163 :
                    attributes = RECORDS[ 1061 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 168 :
                    attributes = RECORDS[ 1067 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 169 :
                    attributes = RECORDS[ 1069 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 170 :
                    attributes = RECORDS[ 1070 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 171 :
                    attributes = RECORDS[ 1071 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 173 :
                    attributes = RECORDS[ 1073 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 174 :
                    attributes = RECORDS[ 1074 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))
                else :
                    attributes = RECORDS[ 1071 ][ 'attributes' ]

                    self.logger.error( 'Unsupported Record/Block Type: Record={0} BlockType={1}'.format( recordType, blockType ) )
                

            elif recordType == 400 :
                blockSubType = struct.unpack(
                                '>' + TYPE_UINT32,
                                data[ 16 : 20 ] )[ 0 ] 
                self.logger.log(logging.TRACE, 'parsing IPS_EVENT blockType {0}'.format(blockSubType))

                if blockSubType == 60 :
                    attributes = RECORDS[  401 ]['attributes']

                    self.logger.log(logging.TRACE, 'IPS BLOCK {0} attributes={1}'.format(blockType, attributes))

                elif blockSubType == 81 :
                    attributes = RECORDS[ 402 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                elif blockSubType == 85 :
                    attributes = RECORDS[ 400 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing IPS event {0} : attributes={1}'.format(blockType, attributes))

                else :
                    attributes = RECORDS[ recordType ][ 'attributes' ]

                    self.logger.error( 'Unsupported Record/Block Type: Record={0} BlockType={1}'.format( recordType, blockType ) )

            elif recordType == 500 :

                blockSubType = struct.unpack(
                                '>' + TYPE_UINT32,
                                data[ 16 : 20 ] )[ 0 ] 
                self.logger.log(logging.TRACE, 'parsing FILE_EVENT blockType {0}'.format(blockSubType))

                if blockSubType == 79 :
                    attributes = RECORDS[ 501 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing FILE event {0} : attributes={1}'.format(blockType, attributes))

                else :
                    attributes = RECORDS[ recordType ][ 'attributes' ]

            elif recordType == 502 :

                blockSubType = struct.unpack(
                                '>' + TYPE_UINT32,
                                data[ 16 : 20 ] )[ 0 ] 
                self.logger.log(logging.TRACE, 'parsing FILE_MALWARE_EVENT blockType {0}'.format(blockSubType))

                if blockSubType == 79 :
                    attributes = RECORDS[ 503 ]['attributes']

                    self.logger.log(logging.TRACE, 'parsing FILE_MALWARE event {0} : attributes={1}'.format(blockType, attributes))

                else :
                    attributes = RECORDS[ recordType ][ 'attributes' ]

            offset = self._parseAttributes( data, offset, attributes, record )

        except (AttributeError, ValueError) as ex:
            hexRecord = binascii.hexlify( data )
            self.logger.error( 'AttributeError: Record={0}'.format( hexRecord ) )
            self.logger.exception(ex)
            return

        if offset != recordLength:
            msg = '__parse(): Offset ({0}) != recordLength ({1}) for recordType {2} blockType {3}'.format(
                offset,
                recordLength,
                recordType, blockType)

            if offset < recordLength:
                self.logger.warning( msg )

            else:
                raise ParsingException( msg )



    def _eventHeader( self, data ):
        ( recordType, recordLength ) = struct.unpack( '>LL', data[0:8] )

        self.recordType = recordType
        blockType = 0
        #struct.unpack('>'+TYPE_UINT32, data[8:12])[0] epoch time for IPS events
        #struct.unpack('>'+TYPE_UINT32, data[12:16])[0]  reserved IPS events

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log(
                logging.TRACE,
                '_eventHeader recordType={0} blockType={1} | data={2} | hex={3}'.format(
                    recordType,
                    blockType, data,  binascii.hexlify( data ) ))

        offset = 0

        record = {
            'recordType': recordType,
            'recordLength': recordLength,
            'blockType': blockType
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

 #       if self.recordType == 400 :
 #           (blockType, ) = struct.unpack('>'+TYPE_UINT32, data[16:20])
 #       else :
 #           (blockType, ) = struct.unpack('>'+TYPE_UINT32, data[offset: (offset + 4) ])

#        self.blockType = blockType

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log(
                logging.TRACE,
                '_eventHeader recordType={0} blockType={1} | data={2} | hex={3}'.format(
                    recordType,
                    blockType, data,  binascii.hexlify( data ) ))

#        record[ 'blockType' ]  = blockType

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

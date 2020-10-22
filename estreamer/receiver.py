
#********************************************************************
#      File:    receiver.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       This file contains the code which connects to the eStreamer
#       server, issues requests and does the minimum parsing required
#       to send binary messages on to the callback
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
import struct
import time

import estreamer
import estreamer.adapters.base64
import estreamer.definitions as definitions
import estreamer.crossprocesslogging as logging
import estreamer.message

from estreamer.common import convert

# We are allowed to catch Exceptions here
#pylint: disable=W0703

class Receiver( object ):
    """
    Receiver opens a host connection and sends an Event Stream Request.
    It then handles responses with the provided callback
    """
    def __init__( self, settings, logQueue, callback ):
        self.connection = None
        self.settings = settings
        self.callback = callback
        self.sequence = 0

        # Configure logging first
        logging.init( logQueue, settings.logging.levelId )
        self.logger = logging.getLogger( self.__class__.__name__ )



    def _ack( self ):
        self.connection.request( estreamer.message.NullMessage() )



    def _requestStreamingInformation( self, responseMessage ):
        offset = 0
        serviceId = 0
        gotService = False

        while offset < len( responseMessage['data'] ):
            weeBuffer = responseMessage['data'][offset:offset+8]

            ( serviceId, length ) = struct.unpack( '>LL', weeBuffer )

            if serviceId == definitions.MESSAGE_STREAMING_INFORMATION_REQUEST_SERVICE_ID:
                gotService = True
                break

            offset = offset + 8 + length

        if not gotService:
            raise estreamer.EncoreException( 'No StreamingInformation service' )

        serviceMessage = estreamer.message.StreamingRequestMessage( self.settings )

        messageHex = binascii.hexlify( serviceMessage.getWireData() )
        self.logger.info( 'StreamingRequestMessage: {0}'.format(messageHex) )

        self.connection.request( serviceMessage )



    def _parseMessageBundle( self, messageBundle ):
        if self.logger.isEnabledFor( logging.VERBOSE ):
            self.logger.log( logging.VERBOSE, 'Processing message bundle')

        offset = 8

        while offset < messageBundle['length']:

            (messageType, length) = struct.unpack('>LL', messageBundle['data'][offset:offset+8] )

            if messageType != definitions.MESSAGE_TYPE_EVENT_DATA :
                raise estreamer.ParsingException(
                    'Bundle item expected MESSAGE_TYPE_EVENT_DATA but got: {0}'.format(messageType))

            message = {
                'version': 1,
                'messageType': messageType,
                'length': length
            }

            if length > 0:
                dataStart = offset + 8
                dataEnd = offset + 8 + length
                message['data'] = messageBundle['data'][ dataStart : dataEnd ]

            self._send( message )

            offset = offset + 8 + length



    def init( self ):
        """
        One off initialisation
        """
        self.connection = estreamer.Connection( self.settings )
        self.connection.connect()

        timestamp = self.settings.initialTimestamp()
        flags = self.settings.requestFlags()

        eventMessage = estreamer.message.EventStreamRequestMessage( timestamp, flags )

        self.logger.debug('Initial request (Timestamp: {0} [{1}]).'.format(
            timestamp,
            convert.toIso8601( timestamp )))

        messageHex = binascii.hexlify( eventMessage.getWireData() )
        self.logger.info( 'EventStreamRequestMessage: {0}'.format(messageHex) )

        self.connection.request( eventMessage )



    def _send( self, message ):
        self.sequence += 1
        message['sequence'] = self.sequence
        self.callback( message )



    def next( self ):
        """
        Call this to attempt to read from the connection. Keep calling it.
        In a loop
        """
        try:
            message = self.connection.response()

            if message['messageType'] == definitions.MESSAGE_TYPE_STREAMING_INFORMATION:
                self._requestStreamingInformation( message )

            elif message['messageType'] == definitions.MESSAGE_TYPE_MESSAGE_BUNDLE:
                self._parseMessageBundle( message )

            elif message['messageType'] == definitions.MESSAGE_TYPE_NULL:
                self.logger.debug( 'Got null message.' )

            elif message['messageType'] == definitions.MESSAGE_TYPE_EVENT_DATA:
                self._send( message )

            elif message['messageType'] == definitions.MESSAGE_TYPE_ERROR:
                messageException = estreamer.MessageErrorException( message )
                self.logger.error( 'FMC Server error: {0}'.format( messageException ) )

            else:
                messageBase64 = estreamer.adapters.base64.dumps( message )
                self.logger.warning( 'Unexpected message: {0}'.format( messageBase64 ) )

            self._ack()

        except estreamer.TimeoutException:
            # A timeout can be fine if there's no data. But timeout we must otherwise
            # we spend all day blocking and never listening on our pipe
            self.logger.debug('FMC sent no data')
            time.sleep( definitions.TIME_PAUSE )

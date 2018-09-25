
#********************************************************************
#      File:    connection.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Manages the connection to the eStreamer Server
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
import datetime
import socket
import ssl
import struct
import time
import estreamer
import estreamer.definitions
import estreamer.crossprocesslogging as logging

class Connection( object ):
    """
    Connection manages the connection to the remote host as well as
    sending and receiving messages
    """
    def __init__( self, settings ):
        self.logger = logging.getLogger( self.__class__.__name__ )
        self.settings = settings
        self.firstReceiveTime = None
        self.lastReceiveTime = None
        self.socket = None
        self.pkcs12 = None



    def connect( self ):
        """
        Opens a secure connection to the remote host
        """
        host = self.settings.host
        port = self.settings.port

        self.pkcs12 = estreamer.Crypto.create( settings = self.settings )

        self.logger.info('Connecting to {0}:{1}'.format(host, port ))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Default TLS
        tlsVersion = ssl.PROTOCOL_TLSv1

        if self.settings.tlsVersion == 1.2:
            if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
                tlsVersion = ssl.PROTOCOL_TLSv1_2
                self.logger.info('Using TLS v1.2')

            else:
                self.logger.warning('PROTOCOL_TLSv1_2 not found. Using TLS v1.0')

        else:
            self.logger.info('Using TLS v1.0')


        self.socket = ssl.wrap_socket(
            sock,
            keyfile = self.pkcs12.privateKeyFilepath,
            certfile = self.pkcs12.certificateFilepath,
            do_handshake_on_connect = True,
            ssl_version = tlsVersion)

        try:
            self.socket.settimeout( self.settings.connectTimeout )
            self.socket.connect( ( host, port ) )

        except socket.timeout:
            raise estreamer.TimeoutException(
                estreamer.definitions.STRING_CONNECTION_COULD_NOT_CONNECT )

        except socket.gaierror as gex:
            # Convert to a nicer exception
            raise estreamer.EncoreException( 'socket.gaierror ({0})'.format(gex) )

        except ssl.SSLError as sslex:
            # Convert to a nicer exception
            raise estreamer.EncoreException(
                estreamer.definitions.STRING_CONNECTION_SSL_ERROR.format(
                    sslex,
                    self.pkcs12.privateKeyFilepath,
                    self.pkcs12.certificateFilepath ) )

        # We're setting the socket to be blocking but with a short timeout
        self.socket.settimeout( self.settings.responseTimeout )



    def close( self ):
        """closes the connection"""
        # self.socket.shutdown( socket.SHUT_RDWR )
        self.socket.close()



    def getFirstReceiveTime( self ):
        """Returns the time when the first message was received this session"""
        return self.firstReceiveTime



    def getLastReceiveTime( self ):
        """Returns the time when the last message was received this session"""
        return self.lastReceiveTime



    def request( self, message ):
        """Issue a request"""
        buf = message.getWireData()

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log(
                logging.TRACE,
                'request({0})'.format( binascii.hexlify( buf ) ))

        self.socket.send( buf )



    def __read( self, want ):
        """Read and return 'want' bytes from the network"""
        dataBuffer = ''
        start = time.time()
        lastGot = 0
        got = 0

        while want > 0:
            try:
                if self.logger.isEnabledFor( logging.TRACE ):
                    self.logger.log(
                        logging.TRACE,
                        'peekBytes = self.socket.recv( {0} )'.format( want ))

                peekBytes = self.socket.recv( want )
                got = len( peekBytes )

                if self.logger.isEnabledFor( logging.TRACE ):
                    self.logger.log(
                        logging.TRACE,
                        'got = {0}'.format( got ))

                if got == 0:
                    # Connection closed.
                    raise estreamer.ConnectionClosedException('Connection closed')

                dataBuffer += peekBytes
                want = want - got

            except socket.error:
                duration = time.time() - start

                if got > lastGot:
                    # If we received data, then reset our time counter
                    lastGot = got
                    start = time.time()

                if duration >= self.settings.responseTimeout:
                    raise estreamer.TimeoutException('Connection read timeout')

        return dataBuffer



    def response( self ):
        """Returns the next response from the wire"""
        self.logger.log( logging.TRACE, 'self.__read(8)')
        dataBuffer = self.__read( 8 )

        (version, messageType, length) = struct.unpack('>HHL', dataBuffer)

        message = {
            'version': version,
            'messageType': messageType,
            'length': length
        }

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log( logging.TRACE, 'header: {0}'.format(
                binascii.hexlify(dataBuffer) ))
            self.logger.log( logging.TRACE, message )

        if version != 1 :
            raise estreamer.EncoreException(
                estreamer.definitions.STRING_CONNECTION_INVALID_HEADER.format(
                    version,
                    message ))

        if version == 1 and messageType != 0:
            self.lastReceiveTime = datetime.datetime.now().now()

            if not self.firstReceiveTime:
                self.firstReceiveTime = self.lastReceiveTime

        if version == 1 and length > 0:
            if self.logger.isEnabledFor( logging.TRACE ):
                self.logger.log( logging.TRACE, 'self.__read({0})'.format(length))

            message['data'] = self.__read( length )

            if self.logger.isEnabledFor( logging.TRACE ):
                self.logger.log( logging.TRACE, 'data: {0}'.format(
                    binascii.hexlify(message['data']) ))

            actualLength = len( message['data'] )
            if length != actualLength:
                raise estreamer.EncoreException(
                    'Expected length {0} but got {1}'.format(
                        length,
                        actualLength))

        if self.logger.isEnabledFor( logging.TRACE ):
            self.logger.log( logging.TRACE, str(message))

        return message

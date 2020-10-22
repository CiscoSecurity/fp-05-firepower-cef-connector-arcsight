
#********************************************************************
#      File:    udp.py
#      Author:  Sam Strachan
#
#      Description:
#       This writes to a udp port with a stream interface
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

import socket
from estreamer.common.convert import isInt
from estreamer.streams.base import Base

# See: # https://wiki.python.org/moin/UdpCommunication

class UdpStream( Base ):
    """Creates a UDP socket and sends messages to it"""
    def __init__( self, host, port, encoding = 'utf-8' ):
        self.host = host
        self.port = port

        # If there's a problem with the host or port, fail fast.
        if len( self.host.strip() ) == 0:
            raise Exception('UdpStream must have a host specified.')

        if not isInt( self.port ):
            raise Exception('UdpStream must have an integer port specified.')

        self.encoding = encoding
        self.socket = None



    def __connect( self ):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.connect( ( self.host, self.port) )



    def close( self ):
        try:
            self.socket.shutdown( socket.SHUT_RDWR )
            self.socket.close()

        except AttributeError:
            pass



    def write( self, data ):
        if self.socket is None:
            self.__connect()

        self.socket.send( data.encode( self.encoding ) )

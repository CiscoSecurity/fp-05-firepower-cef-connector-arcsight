
#********************************************************************
#      File:    base.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Base class for constructing estreamer request messages
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

import struct
import estreamer.definitions as definitions

class Base( object ):
    """Base message encoder"""
    def __init__( self, messageType, packFormat ):
        self.data = [ definitions.MESSAGE_VERSION, 0, 0 ]
        self.messageType = messageType
        self.packFormat = packFormat
        self.messageLength = 0



    def set( self, index, newData ):
        """Allows the setting of a precise piece of data in the message rather
        than through direct access to self.data"""
        self.data[ index ] = newData



    def append( self, moreData, size, extraFormat=None ):
        """Helper function to append additional data into a wire message."""
        self.data.append( moreData )
        self.messageLength += size

        if extraFormat:
            self.packFormat += extraFormat



    def fixData( self ):
        """Sets the message type and length. Must be called just before
        getWireData"""
        self.data[1] = self.messageType
        self.data[2] = self.messageLength



    def getWireData( self ):
        """
        Performs any necessary final adjustments to the message (setting length
        etc) and then formats as a series of bytes ready for transmission
        """
        self.fixData()
        return struct.pack( self.packFormat, *self.data )

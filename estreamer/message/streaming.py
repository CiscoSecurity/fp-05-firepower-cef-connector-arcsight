
#********************************************************************
#      File:    streaming.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Creates a streaming request message.
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

from estreamer.message.base import Base
import estreamer.definitions as definitions

class StreamingRequestMessage( Base ):
    """
    Class represents the Streaming Request Message Format. The format
    is defined on page 45 (2-29) of the 6.0.0 spec
    """
    def __init__( self, settings ):
        super( StreamingRequestMessage, self ).__init__(
            definitions.MESSAGE_TYPE_STREAMING_REQUEST,
            '>HHLLLLL' )

        self.settings = settings
        self.append( definitions.MESSAGE_STREAMING_INFORMATION_REQUEST_SERVICE_ID, 4 )

        # temp slot for the second size (always zero)
        self.append( 0, 4 )
        self.append( self.settings.requestFlags(), 4 )
        self.append( self.settings.initialTimestamp(), 4 )
        self.__appendEvents()



    def fixData( self ):
        super( StreamingRequestMessage, self ).fixData()
        self.set( 4, self.messageLength )



    def __appendEvent( self, event ):
        self.append( event['version'], 2, 'H')
        self.append( event['code'], 2, 'H')



    def __appendEvents( self ):
        # See page 49 / 2-33 of the 6.0.0 spec
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_INTRUSION )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_METADATA )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_CORRELATION )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_DISCOVERY )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_CONNECTION )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_USER )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_MALWARE )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_FILE )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_IMPACT )
        self.__appendEvent( definitions.MESSAGE_EXTENDED_REQUEST_TERMINATE )

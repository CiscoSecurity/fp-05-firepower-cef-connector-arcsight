
#********************************************************************
#      File:    eventstream.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Creates an event stream message - the initial message sent
#       at the start of an eStreamer session
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
from sys import getsizeof
import estreamer.definitions as definitions
import estreamer.settings as settings
import struct
import argparse
import os
import signal
import sys
import time
import estreamer

WORKING_DIRECTORY = os.path.abspath( os.path.dirname(__file__) + '/..')
sys.path.append(WORKING_DIRECTORY) 

class EventStreamRequestMessage( Base ):
    """
    Class which represents the Event Stream Request Message Format.
    Format is defined on page 26+ (or 2-10/11) of the 6.0.0 spec
    """
    def __init__( self, timestamp, flags ):

        super( EventStreamRequestMessage, self ).__init__(
            definitions.MESSAGE_TYPE_EVENT_STREAM_REQUEST,
            '>HHLLL' )
        
        self.append( timestamp, 4 )
        self.append( flags, 4 )
        jsonSettings = estreamer.Settings.create( WORKING_DIRECTORY + "/request.conf" )
    #    self.append( str(jsonSettings.store), getsizeof(str(jsonSettings.store)), 's')
        #New request
#        self.increaseLength( getsizeof( str(settings.store) ) ) 
#        self.append( str(settings.store), getsizeof( str(settings.store)  ), 's')


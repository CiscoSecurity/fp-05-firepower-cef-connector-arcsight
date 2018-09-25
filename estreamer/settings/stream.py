
#********************************************************************
#      File:    stream.py
#      Author:  Sam Strachan
#
#      Description:
#       Stream settings
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
class StreamSettings( object ):
    """Class to define stream settings"""
    def __init__( self, streamSettings ):
        self.uri = streamSettings['uri']
        self.options = {}

        if 'options' in streamSettings:
            for option in streamSettings['options']:
                self.options[option] = streamSettings['options'][option]


#********************************************************************
#      File:    outputter.py
#      Author:  Sam Strachan
#
#      Description:
#       Outputter settings
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

from estreamer.settings.stream import StreamSettings

class OutputterSettings( object ):
    """Class to define outputter settings"""
    def __init__( self, outputterSettings ):
        self.adapter = outputterSettings['adapter']
        self.enabled = outputterSettings['enabled']
        self.passthru = False

        if 'passthru' in outputterSettings:
            self.passthru = outputterSettings['passthru']

        self.stream = StreamSettings( outputterSettings['stream'] )


#********************************************************************
#      File:    enabled.py
#      Author:  Sam Strachan
#
#      Description:
#       Returns status of settings.enabled
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

from estreamer.condition.base import BaseCondition
import estreamer

class EnabledCondition( BaseCondition ):
    """Class for evaluating if settings.enabled is true"""
    def __init__( self, settingsFilepath ):
        super( EnabledCondition, self ).__init__()
        self.settingsFilepath = settingsFilepath

    def isTrue( self ):
        if self.settingsFilepath:
            settings = estreamer.Settings.create( self.settingsFilepath )
            return settings.enabled

        return False

    def message( self ):
        return 'settings.enabled == False.'

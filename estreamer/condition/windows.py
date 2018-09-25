
#********************************************************************
#      File:    windows.py
#      Author:  Sam Strachan
#
#      Description:
#       Returns status of windows key event
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

class WindowsCondition( BaseCondition ):
    """Class for evaluating if settings.enabled is true"""
    def __init__( self ):
        super( WindowsCondition, self ).__init__()

    def isTrue( self ):
        # Check to see if the user has pressed return
        from msvcrt import getch, kbhit
        if kbhit() and ord( getch() ) == 13:
            return False

        return True

    def message( self ):
        return 'User pressed <enter>.'

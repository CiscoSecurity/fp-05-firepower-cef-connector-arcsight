
#********************************************************************
#      File:    monitor.py
#      Author:  Sam Strachan
#
#      Description:
#       Monitor settings
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

class MonitorSettings( object ):
    """Class to define monitor settings"""
    def __init__( self, monitorSettings ):
        self.period = 120
        self.velocity = False
        self.bookmark = False
        self.subscribed = False
        self.handled = True
        self.details = False

        if monitorSettings:
            self.period = monitorSettings['period']
            self.velocity = monitorSettings['velocity']
            self.bookmark = monitorSettings['bookmark']
            self.subscribed = monitorSettings['subscribed']
            self.handled = monitorSettings['handled']

            if 'details' in monitorSettings:
                self.details = monitorSettings['details']

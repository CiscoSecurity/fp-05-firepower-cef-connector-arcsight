
#********************************************************************
#      File:    base.py
#      Author:  Sam Strachan
#
#      Description:
#       Base condition
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

class BaseCondition( object ):
    """Base class for evaluating continuation conditions"""
    def __init__( self ):
        pass

    def isTrue( self ):
        """Returns the condition's state"""
        return False

    def message( self ):
        """Message to return if false"""
        return 'Base condition error'

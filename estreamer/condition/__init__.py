
#********************************************************************
#      File:    __init__.py
#      Author:  Sam Strachan
#
#      Description:
#       condition package
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

from estreamer.condition.enabled import BaseCondition as _BaseCondition
from estreamer.condition.enabled import EnabledCondition
from estreamer.condition.splunk import SplunkCondition
from estreamer.condition.windows import WindowsCondition
from estreamer.exception import EncoreException

def create( name ):
    """Factory method for conditions"""
    if name == 'splunk':
        return SplunkCondition()

    elif name == 'base':
        return _BaseCondition()

    else:
        raise EncoreException('Unrecognised condition: {0}'.format( name ))

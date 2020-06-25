"""
Transforms to a Plain old Python object string
"""
#********************************************************************
#      File:    popo.py
#      Author:  Sam Strachan
#
#      Description:
#       POPO adapter
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

import ast
import pprint

def __loads( line ):
    """Converts a string line back into a dict. But note
    that dumps() changes the outgoing object by making
    data safe so this function is not a true inverse.
    Therefore it has been deliberately marked private"""
    return ast.literal_eval( line )

def dumps( data, formatted = True ):
    """Serializes the incoming object as a pickled base64 string"""
    if not formatted:
        return str ( data )
    else:
        return pprint.pformat( data, indent = 4, width = 96, depth = None )

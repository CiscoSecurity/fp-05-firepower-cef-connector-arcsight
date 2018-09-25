"""Transforms to and from a base64 line and a dict"""
#********************************************************************
#      File:    base64.py
#      Author:  Sam Strachan
#
#      Description:
#       Base64 adapter
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

from __future__ import absolute_import

import base64
import pickle
import estreamer.crossprocesslogging as logging

def loads( line ):
    """Converts a pickled base64 line back into a dict"""
    byteArray = line.rstrip().decode('base64', 'strict')
    try:
        dictionary = pickle.loads( byteArray )
        return dictionary
    except ValueError as ex:
        logging.getLogger(__name__).warning(ex)
        return None



def dumps( data ):
    """Serializes the incoming data as a pickled base64 string"""
    byteArray = pickle.dumps( data )
    string = base64.b64encode( byteArray )
    return string

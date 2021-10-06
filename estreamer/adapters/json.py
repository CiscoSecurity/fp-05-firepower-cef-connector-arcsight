"""
Transforms to and from JSON and a dict
"""
#********************************************************************
#      File:    json.py
#      Author:  Sam Strachan
#
#      Description:
#       JSON adapter
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
import json

class UTF8Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return str(obj, encoding='utf-8');
        return json.JSONEncoder.default(self, obj)

def loads( line ):
    """Converts a json line back into a dict"""
    return json.loads( line )

def dumps( data ):
    """Serializes the incoming object as a json string"""
    return json.dumps(data,cls=UTF8Encoder)

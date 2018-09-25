
#********************************************************************
#      File:    utils.py
#      Author:  Sam Strachan
#
#      Description:
#       common utils
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

def extend( toExtend, extendWith ):
    """
    Extends toExtend and merges the extendWith object with into
    toExtend. If toExtend and extendWith have the same attributes then
    whatever is in extendWith will overwrite toExtend
    """
    for key in extendWith:
        value = extendWith[key]

        if isinstance(value, list):
            extend( toExtend[key], value )
        else:
            toExtend[key] = value



def __flatten( context, namespace, output ):
    for key in context:
        value = context[key]

        if isinstance(value, dict) and len(value) > 0:
            __flatten( value, namespace + key + '.', output)
        else:
            output[namespace + key] = value



def flatten( data ):
    """Takes an object graph and flattens it into a single
    layer dict. keys are pseudo-namespaced using a dot "."
    separator

    e.g.
    {
        'foo': 'bar',
        'fu': {
            'foo', 'bar'
        }
    }

    becomes
    {
        'foo': 'bar',
        'fu.foo': 'bar'
    }
    """
    output = {}
    __flatten( data, '', output )
    return output

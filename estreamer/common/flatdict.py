
#********************************************************************
#      File:    flatdict.py
#      Author:  Sam Strachan
#
#      Description:
#       Wrapper class to access a hierarchical dict with flat dot
#       delimited keys
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

#pylint: disable=W0104

class Flatdict( object ):
    """
    Wrapper class for a dictionary which allows read-only flattened key access to a
    nested graph. E.g. instead of record['user']['name'] use record['user.name']
    """
    def __init__( self, dictionary, ignoreKeyErrors = False ):
        self.store = dictionary
        self.ignoreKeyErrors = ignoreKeyErrors



    def __getitem__( self, key ):
        if isinstance( key, basestring ):
            keys = key.split('.')
            data = self.store
            for item in keys:
                if item in data:
                    data = data[ item ]

                elif self.ignoreKeyErrors:
                    return None

                else:
                    raise KeyError(item)

            return data

        else:
            return self.store[ key ]



    def __iter__( self ):
        return iter( self.store )



    def __len__( self ):
        return len( self.store )



    def __contains__( self, key ):
        try:
            self[ key ]
            return True
        except KeyError:
            return False

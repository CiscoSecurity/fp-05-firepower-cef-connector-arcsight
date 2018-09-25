
#********************************************************************
#      File:    bookmark.py
#      Author:  Sam Strachan
#
#      Description:
#       Manages reading and writing to a bookmark file
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

import json
import os
import estreamer.crossprocesslogging as logging

class Bookmark( object ):
    """The bookmark class abstracts reading, writing and managing bookmarks"""
    def __init__( self, filepath ):
        self.store = {}
        self.logger = logging.getLogger( self.__class__.__name__ )
        self.filepath = filepath
        self.isDirty = False

        if not os.path.exists( filepath ):
            self.logger.info('Bookmark file {0} does not exist.'.format( filepath ))

        else:
            with open( filepath, 'r' ) as reader:
                try:
                    self.store = json.loads( reader.read() )
                    self.logger.info('Opening bookmark file {0}.'.format( filepath ))
                except ValueError:
                    self.logger.info(
                        'Bookmark file {0} in unexpected format.'.format( filepath ))

                    self.store = {}

            # Just in case someone has put something weird in the file
            if not isinstance( self.store, dict ):
                self.store = {}



    def save( self ):
        """Saves the current bookmarks"""
        if self.isDirty:
            if self.logger.isEnabledFor( logging.VERBOSE ):
                self.logger.log( logging.VERBOSE, 'Saving {0}'.format( str( self.store ) ))

            with open( self.filepath, 'w' ) as bookmarkFile:
                bookmarkFile.write( json.dumps( self.store ) )

            self.isDirty = False



    def write( self, timestamp ):
        """Writes a time from a specified source"""
        source = '1'
        if source not in self.store:
            self.store[ source ] = timestamp
            self.isDirty = True

        elif timestamp > self.store[ source ]:
            self.store[ source ] = timestamp
            self.isDirty = True



    def read( self ):
        """Reads the time from a specified source"""
        source = '1'
        if source in self.store:
            if isinstance( self.store[ source ], int ):
                return self.store[ source ]

        return 0

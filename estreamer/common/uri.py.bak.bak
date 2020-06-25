
#********************************************************************
#      File:    uri.py
#      Author:  Sam Strachan
#
#      Description:
#       URI parser class
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

import re
from estreamer.exception import ParsingException

class StringReader( object ):
    """Helper class to read until specific tokens in a string"""
    def __init__( self, string ):
        self.string = string
        self.cursor = 0



    def shift( self, amount ):
        """Shifts the cursor along by a specified amount"""
        self.cursor += amount



    def read( self, tokens ):
        """Reads until the next token"""
        index = -1

        if isinstance( tokens, basestring ):
            tokens = [ tokens ]

        for token in tokens:
            val = self.string.find( token, self.cursor )
            if val > -1:
                index = val

        if index == -1:
            index = len( self.string )

        value = self.string[ self.cursor : index ]
        self.cursor = index

        return value



    def index( self, token ):
        """Finds the next token after the current cursor position"""
        return self.string.find( token, self.cursor )



class Uri( object ):
    """Parses a URI into its consituent parts"""
    def __init__( self, uri ):
        self.uri = uri

        uriReader = StringReader( uri )

        self.scheme = uriReader.read( ':' )

        if uri[ uriReader.cursor + 1 : uriReader.cursor + 3] != '//':
            raise ParsingException(
                'Uri does not contain "//". Expected form is ' +
                'scheme://authority/path?query#fragment. "authority" ' +
                'can be empty when scheme = file' )

        uriReader.shift( 3 )
        self.authority = uriReader.read( '/' )
        self.fullpath = uriReader.read( '?' )
        uriReader.shift( 1 )
        self.query = uriReader.read( '#' )
        uriReader.shift( 1 )
        self.fragment = uriReader.read( '\0' )

        self.host = None
        self.port = None
        self.userinfo = None

        if len( self.authority ) > 0:
            authorityReader = StringReader( self.authority )

            if authorityReader.index( '@' ) > -1:
                self.userinfo = authorityReader.read( '@' )
                authorityReader.shift( 1 )

            self.host = authorityReader.read( ':' )

            try:
                authorityReader.shift( 1 )
                self.port = int( authorityReader.read( '\0' ) )

            except ValueError:
                pass

        lastSlash = self.fullpath.rfind('/')
        self.path = self.fullpath[ : lastSlash]
        self.file = self.fullpath[ lastSlash + 1 : ]

        # If this is a relative file, OR it's windows with a FULL path then we need to remove
        # the leading slash. If it's windows then it will look like '/C:/'
        if self.scheme == 'relfile' or re.match('/[A-Za-z]:/', self.path):
            self.fullpath = self.fullpath[1:]
            self.path = self.path[1:]

        # If this is an SCP path with a colon at the start then it's relative to the remote
        # home directory. Start *after* the colon
        elif re.match('/:', self.path ):
            self.fullpath = self.fullpath[2:]
            self.path = self.path[2:]
            
"""
The metadata package contains all the definitions and classes
to manage metadata and standard computed values from eStreamer
"""
#********************************************************************
#      File:    __init__.py
#      Author:  Sam Strachan
#
#      Description:
#       metadata package
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

# Allow invalid constant name, use of global and wildcard import
#pylint: disable=C0103,W0603

from estreamer.metadata.cache import Cache
from estreamer.metadata.view import View

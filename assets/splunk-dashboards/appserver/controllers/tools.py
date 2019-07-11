#!/usr/bin/env python
###############################################################################
#
# Copyright (C) 2013-2014 Cisco and/or its affiliates. All rights reserved.
#
# THE PRODUCT AND DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY
# KIND, AND CISCO DISCLAIMS ALL WARRANTIES AND REPRESENTATIONS, EXPRESS OR
# IMPLIED, WITH RESPECT TO THE PRODUCT, DOCUMENTATION AND RELATED MATERIALS
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE; WARRANTIES ARISING FROM A COURSE OF
# DEALING, USAGE OR TRADE PRACTICE; AND WARRANTIES CONCERNING THE
# NON-INFRINGEMENT OF THIRD PARTY RIGHTS.
#
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY DAMAGES RESULTING FROM LOSS OF
# DATA, LOST PROFITS, LOSS OF USE OF EQUIPMENT OR LOST CONTRACTS OR FOR ANY
# SPECIAL, INDIRECT, INCIDENTAL, PUNITIVE, EXEMPLARY OR CONSEQUENTIAL
# DAMAGES IN ANY WAY ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THE PRODUCT OR DOCUMENTATION OR RELATING TO THIS
# AGREEMENT, HOWEVER CAUSED, EVEN IF IT HAS BEEN MADE AWARE OF THE
# POSSIBILITY OF SUCH DAMAGES.  CISCO'S ENTIRE LIABILITY TO LICENSEE,
# REGARDLESS OF THE FORM OF ANY CLAIM OR ACTION OR THEORY OF LIABILITY
# (INCLUDING CONTRACT, TORT, OR WARRANTY), SHALL BE LIMITED TO THE LICENSE
# FEES PAID BY LICENSEE TO USE THE PRODUCT.
#
################################################################################
#
#  ChangeLog
#
#   1.0  - CGrady - ORIGINAL RELEASE WITH INTRODUCTION OF SPLUNK APP
#
################################################################################


################################################################################
#  Import modules
################################################################################

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route


################################################################################
#  tools class
################################################################################

class tools(controllers.BaseController):

  # Define the savepcap tool endpoint
  @expose_page(must_login=True)
  def savepcap(self, **kwargs):
    
    # Set the defaults
    output = ''
    error = 0
    
    # Get the event ID and PCAP values
    event_id = kwargs.get('event_id', '')
    packet   = kwargs.get('packet', '')
    
    # If we have an event ID and PCAP, then...
    if (len(event_id) and len(packet)):
      
      # Add the PCAP header to the packet
      pcap = 'd4c3b2a1020004000000000000000000ffff010001000000' + packet
      
      # Define the output as the decoded PCAP
      try:
        output = pcap.decode('hex')
      except TypeError as detail:
        # We have an error
        error = 1
        output = 'Something is wrong with the pcap string: %s' % detail
      
    # If we don't have what we need, then...
    else:
      error = 1
      output = 'We do not have the information we want.'
    
    # If we had an error, we'll be printing just text
    if (error):
      cherrypy.response.headers['Content-Type'] = 'text/plain'
      
    # Otherwise we're providing a PCAP
    else:
      cherrypy.response.headers['Content-Type'] = 'application/vnd.tcpdump.pcap'
      cherrypy.response.headers['Content-Disposition'] = 'attachment; filename=%s.pcap' % event_id
    
    # Provide the output
    return output

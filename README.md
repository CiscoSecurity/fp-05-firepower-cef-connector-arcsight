# License

Copyright (c) 2017 by Cisco Systems, Inc.

[Cisco EULA](http://www.cisco.com/c/en/us/about/legal/cloud-and-software/software-terms.html)

    ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
    OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
    INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
    PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
    CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.

# eStreamer eNcore
The SourceFire eStreamer client. 

The Cisco Event Streamer (also known as eStreamer) allows you to stream System intrusion,
discovery, and connection data from Firepower Management Center or managed device (also
referred to as the eStreamer server) to external client applications.

eStreamer responds to client requests with terse, compact, binary encoded messages – this
keeps it fast.

eNcore is a new all-purpose client which requests all possible events from eStreamer, parses
the binary content and outputs events in various formats to support other SIEMs.

# Support
This is a beta version of eNcore. Before the General Availability release this will be
updated with details of paying for and receiving support.

# Quick install
* Download the release: eStreamer-eNcore-X.YY.tar.gz
* Navigate to the directory you want to contain eStreamer eNcore
* `tar -xf eStreamer-eNcore-X.YY.tar.gz`
* `cd eStreamer-eNcore`
* Run eNcore: `./encore.sh`
* Run a connectivity test: `./encore.sh test` (and enter the pkcs12 password)
* View the log output `tail -f estreamer.log`
* `./encore.sh foreground` - run in the foreground
* `./encore.sh start` - starts a background task
* `./encore.sh stop` - this will stop the background task
* `./encore.sh restart` - this will restart the background task

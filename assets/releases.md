# Release history

## v3.5.4 

  * Include release history #95
  * Fix eNcore ignores settings which control writing of metadata #92
  * Add performance / workerProcesses / batchSize notes to readme #97

## v3.5.3 Parse Error Handling and Improved Logging
released this on Sep 4 · 1 commit to master since this release

  * For parse errors #94 , will now log a warning and the record, and continue
    processing the next record.
  * The configuration file is written to the log when eNcore starts.

## v3.5.2 Patch for New Record Types
released this on Aug 24 · 10 commits to master since this release

  * This patch corrects a problem where eNcore may crash if it receives a record
    type that it is not programmed to handle ( #93 ).

## v3.5.1 Decorator Process Patch
released this on Aug 1 · 24 commits to master since this release

  * This release patches a problem (issue #76) with the decorator process that
    was causing eNcore to crash.

## v3.5.0 Performance and CEF updates
released this on Jul 5 · 30 commits to master since this release

  * Removed fw_policy from Splunk output in 502 file events #85
  * Fixed metadata for source user (suser) in connection, intrusion, file and
    malware events #82

## v3.5.0.rc.3 Performance and CEF updates
released this on Jun 12 · 36 commits to master since this release

  * Add "workerProcesses": 4 in default.conf bug #75
  * eNcore output contains original SID, not rendered SID #78
  * eNcore cache not written to disk #80
  * Child process poll timeout #83

## v3.5.0.rc.1 Performance and CEF updates
released this on May 1 · 45 commits to master since this release

  * CEF message crash (UnicodeEncodeError: 'ascii' codec can't encode characters
    in position 115-118: ordinal not in range(128)) bug #59
  * CEF:Packet - invalid characters bug #57
  * CEF:71:cs2 incorrect bug #56
  * CEF:71:cs1 incorrect bug #55
  * Intrusion event missing metadata for interfaceEgress (View.IFACE_EGRESS)
    bug #53
  * Handle all possible errors in connection bug #52
  * Major performance updates
  * CEF: added Packet handling #49
  * CEF: Corrected message escaping
  * Splunk: Added dest_ip_country from metadata #45
  * General: Removed maxQueueSize from config #48
  * General: Minor changes to stream package (rename / refactor)
  * General: Added SCP stream
  * General: Changes to pyOpenSSL imports - no longer fails if pyOpenSSL is not
    needed and not installed #47
  * Splunk dashboard: incorrect assignment of tags #36
  * Bad splunk mapping for rec_type=125 #37
  * Error while posting to url=/servicesNS/nobody/TA-eStreamer/encore/configure/main #35
  * Splunk: device_id field is missing from most records #50

## v3.0.0 Initial release with Splunk
released this on Aug 1, 2017 · 174 commits to master since this release

  * Multiprocessing.Queue now uses max size rather than dynamic checking
  * Major changes to shell scripts
  * Moved shell script logic into python for cross-platform re-usability
  * Added "Condition" architecture - Service now checks for extensible
    conditions e.g. is Splunk running? Has a user pressed a certain key
    (Windows)? Is settings.enabled == true?
  * Major packaging updates
  * Added Splunk technical add-on (TA-eStreamer) and app (eStreamer-Dashboards)
    - and it uses packaging to create the packages automatically
  * Changes to the service class for reliability and logging
  * Improved error messages if SSL certificate is "revoked"
  * Moved PID handing into Service instead of shell script - more reliable if
    the program stops
  * Changed configuration to switch "connections" (recType=71) on and off
    instead of "flows"
  * Added stdout / stderr logging options
  * Refactored settings.py into a module / package
  * Improved ctrl-C handling so it works in Windows now

## v1.03 General availability
released this on Jun 23, 2017 · 324 commits to master since this release

  * Fixed error message where PKCS12 password is requested in background task
  * Improved logging
  * General fix for malformed metadata - log and continue
  * Log and continue on FMC error
  * Fixed issue where CPU remains high on empty queue

## v1.02 Limited availability beta 3
released this on May 31, 2017 · 333 commits to master since this release

  * Improved error message for CSCve44987
  * Improved error logging with bad messages
  * Optional switch for restart on error. Off by default
  * Fixed metadata lookup for device linked ACPs - fw_policy on 71 & 400
  * Flush file buffers on write to minimise broken lines
  * Escape new lines in data for Splunk
  * Fixed encore.sh for dash shell

## v1.01 Limited availability beta 2
released this on May 10, 2017 · 368 commits to master since this release

  * Fixed parsing errors for zero length variables at the end of a record
  * Added significant TRACE level logging at the connection level
  * Fixed a log level defect (would not support anything other than INFO)
  * Shell script fixes
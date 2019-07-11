#!/bin/sh

# debug
# set -x

#SPLUNK_HOME=/opt/splunk

# vars
pid='-1'
configFilepath="estreamer.conf"
pybin="python"
basepath="$SPLUNK_HOME/etc/apps/$$APP_ID/bin/encore/"
isRunning=0

# constants
configure="$pybin ./estreamer/configure.py $configFilepath"
diagnostics="$pybin ./estreamer/diagnostics.py $configFilepath"
service="$pybin ./estreamer/service.py $configFilepath"
preflight="$pybin ./estreamer/preflight.py $configFilepath"

pidFile="encore.pid"

EXIT_CODE_ERROR=0

init() {
    # change pwd
    if [ -d $basepath ]
    then
        cd $basepath
    
    else
        echo "\"$basepath\" does not exist"
        exit $EXIT_CODE_ERROR

    fi

    if [ ! -e "$configFilepath" ]
    then
        cp default.conf $configFilepath
    fi
}

preflight() {
    $preflight --nostdin
    ok=$?
    if [ "$ok" -ne 0 ]
    then
        exit $EXIT_CODE_ERROR
    fi

    pidFile=`$configure --print pidFile`
    pid=`$configure --print pid`

    # Work out if we're running already
    ps ax | grep -F -- $pid | grep -v 'grep' > /dev/null 2>&1
    process=$?

    if [ $pid = '-1' ]
    then
        : #echo "Checking pid.... none found."

    elif [ $process -eq 1 ]
    then
        # echo "Stale pidFile ($pid). Removing"
        rm $pidFile
        pid=-1

    elif [ $process -eq 0 ]
    then
        # echo "$service ($pid) is running."
        isRunning=1

    fi
}

diagnostics() {
    $diagnostics
}

foreground() {
    $service
}

stop() {
    ps ax | grep -F -- $pid | grep -v 'grep' > /dev/null 2>&1
    process=$?

    if [ $isRunning -eq 0 ]
    then
        echo "Splencore not running"

    else
        echo "Splencore found pid. Terminating \"$service\" ($pid)"
        kill -s INT $pid

        # Wait for the process to finish
        while [ 1 ]
        do
            # Do not redirect stdErr - Splunk no likey
            ps ax | grep -F -- $pid | grep -v 'grep' > /dev/null #2>&1
            process=$?

            if [ $process -eq 1 ]
            then
                break
            fi

            sleep 0.5
        done

        pid='-1'
        sleep 1

    fi
}
 
status() {
    $configure --print splunkstatus
}

clean() {
    # Delete data older than 12 hours -> 720mins
    find ../../data -type f -mmin +720 -delete
}

main() {
    case "$1" in
        test)
            init
            preflight
            diagnostics
            ;;

        start)
            init
            preflight
            foreground
            ;;

        stop)
            init
            preflight
            stop
            ;;

        status)
            init
            status
            ;;

        clean)
            init
            clean
            ;;

        *)
            echo $"Usage: $prog { start | stop | test | status | clean }"
            echo
            echo '    start:      starts eNcore'
            echo '    stop:       stops eNcore'
            echo '    test:       runs a quick test to check connectivity'
            echo '    status:     returns the current status in a splunk way'
            echo '    clean:      removes data older than 12 hours'
            echo
            echo $1
            exit $EXIT_CODE_ERROR

    esac
}

main $1

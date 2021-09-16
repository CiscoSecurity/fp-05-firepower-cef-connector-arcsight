#!/bin/sh

# debug
# set -x

# vars
pid=-1
configFilepath="estreamer.conf"
pybin="python3"
basepath="."
isRunning=0

# constants
configure="$pybin ./estreamer/configure.py $configFilepath"
diagnostics="$pybin ./estreamer/diagnostics.py $configFilepath"
service="$pybin ./estreamer/service.py $configFilepath"
preflight="$pybin ./estreamer/preflight.py $configFilepath"
pidFile="encore.pid"

EXIT_CODE_ERROR=1

# change pwd
cd $basepath

setup() {
    $configure --enabled=true
    read -p 'Would you like to output to (1) Splunk, (2) CEF or (3) JSON?' input

    if [ "$input" = "1" ]
    then
        $configure --output=splunk

        echo 'If you wish to change where data is written to then edit estreamer.conf '
        echo 'and change $.handler.outputters[0].stream.uri'
        echo

    elif [ "$input" = "2" ]
    then
        $configure --output=cef

        echo 'You need to set the target syslog server and port; edit estreamer.conf '
        echo 'and change $.handler.outputters[0].stream.uri'
        echo

    elif [ "$input" = "3" ]
    then
        $configure --output=json

        echo 'If you wish to change where data is written to then edit estreamer.conf '
        echo 'and change $.handler.outputters[0].stream.uri'
        echo

    else
        echo 'No changes made'
        echo
        exit $EXIT_CODE_ERROR
    fi
}

init() {
    pythonVersion=`$pybin -V 2>&1 | grep "Python 3*"`
#    echo "Python Version " + sys.version()

    if [ ! -e "$configFilepath" ]
    then
        cp default.conf $configFilepath
        setup
    fi

    $preflight
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

start() {
    if [ $isRunning -eq 0 ]
    then
        echo -n "Starting \"$service\". "
        $service > /dev/null 2>&1 &
        sleep 1

        pid=`$configure --print pid`
        echo "Started. pid=$pid"

    else
        echo "$service is already running."

    fi
}

stop() {
    if [ $isRunning -eq 0 ]
    then
        echo "Not running"

    else
        echo "Found pid. Terminating \"$service\" ($pid)"
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
        isRunning=0
        sleep 1

    fi
}

ts() {
    tar -zcvf ../"encore-ts-$(date '+%Y-%m-%d_%H-%M-%S%z(%Z)').tar.gz" *
}

restart() {
    stop
    start
}

main() {
    case "$1" in
        start)
            start
            ;;

        stop)
            stop
            ;;

        restart)
            restart
            ;;

        test)
            diagnostics
            ;;

        foreground)
            foreground
            ;;
	
        ts)
	        ts
	        ;;
	     
        setup)
            setup
            ;;

        *)
            echo $"Usage: $prog {start | stop | restart | foreground | test | setup}"
            echo
            echo '    start:      starts eNcore as a background task'
            echo '    stop:       stop the eNcore background task'
            echo '    restart:    stop the eNcore background task'
            echo '    foreground: runs eNcore in the foreground'
            echo '    test:       runs a quick test to check connectivity'
            echo '    setup:      change the output (splunk | cef | json)'
            echo
            echo $1
            exit $EXIT_CODE_ERROR

    esac
}

init
main $1

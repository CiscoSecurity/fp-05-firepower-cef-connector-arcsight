#!/bin/sh

# debug
# set -x

# vars
pid=-1
configFilepath="estreamer.conf"
pybin="python"
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
    pythonVersion=`$pybin -V 2>&1 | grep "Python 2.7"`
    if [ "$pythonVersion" != "" ]
    then
        : #echo 'Python 2.7 is installed'
    else
        echo 'Python 2.7 is not available'
        echo
        echo 'It may be that you have both or neither python 2.x and 3.x installed but that your'
        echo 'environment is not set up correctly. To see:'
        echo
        echo '    which python'
        echo 'and'
        echo '    whereis python'
        echo
        echo 'It is also possible that you have conflicting versions of python installed.'
        echo 'Wherever possible, try to use a default system install located at /usr/bin/python'
        echo
        exit $EXIT_CODE_ERROR
    fi

    # This only seems necessary on Linux outside of Splunk
    pyMaxUnicodeOk=`$pybin -c 'import sys; print(0x10000 < sys.maxunicode)'`
    if [ "$pyMaxUnicodeOk" = "False" ]
    then
        pyPath=`which python`

        echo 'Incompatible build of python'
        echo
        echo 'eNcore requires the standard version of python built with PyUnicodeUCS4. You are'
        echo 'seeing this error message because the currently executing version of python'
        echo "($pyPath) is built with PyUnicodeUCS2."
        echo
        echo 'This is a known issue in certain cases when running as the splunk user (more here:'
        echo 'https://answers.splunk.com/answers/327336/why-am-i-getting-importerror-undefined-symbol-pyun.html)'
        echo
        echo 'The solution is to create a new user with the standard python environment and run'
        echo 'as that user.'
        echo
        exit $EXIT_CODE_ERROR
    fi

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

    $configure --enabled=true

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

clean() {
    # Delete data older than 12 hours -> 720mins
    find ../../data -type f -mmin +720 -delete
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

        clean)
            clean
            ;;

        foreground)
            foreground
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

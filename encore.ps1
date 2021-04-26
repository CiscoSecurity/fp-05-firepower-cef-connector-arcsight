#!/bin/sh -> To PowerShell!
#Created by: Nicholas Penning

# debug
# set -xcd

# vars
$processpid = -1
$configFilepath = "estreamer.conf"
$pybin = "python"
$basepath = "."
$isRunning = 0

# constants
$configure = "./estreamer/configure.py" #$configFilepath
$diagnostics = "./estreamer/diagnostics.py" #$configFilepath
$service = "./estreamer/service.py" #$configFilepath
$preflight = "./estreamer/preflight.py" #$configFilepath
$pidFile = "encore.pid"
$prog = "encore.ps1"

#Change coding to prevent some Windows specific errors (LookupError: unknown encoding: cp65001)
[Console]::OutputEncoding = [System.Text.Encoding]::Default

$EXIT_CODE_ERROR = 1

# change pwd
Set-Location $basepath

if (Test-Path -Path *.pid){
    Write-Output "Removing stale pidFile."
    Remove-Item *.pid
    $processpid = -1
}

#Other things you might need: python -m pip install win_inet_pton

function setup {
    & $pybin $configureNew $configFilepath "--enabled=true"

    #read -p 'Would you like to output to (1) Splunk, (2) CEF or (3) JSON?' choice
    $choice = Read-Host "Would you like to output to (1) Splunk, (2) CEF or (3) JSON?" 

    if ($choice -eq "1"){
        & $pybin $configure $configFilepath "--output=splunk"

        Write-Output 'If you wish to change where data is written to then edit estreamer.conf '
        Write-Output 'and change $.handler.outputters[0].stream.uri'
        Write-Output ''
    }elseif ($choice -eq "2"){
        & $pybin $configure $configFilepath "--output=cef"

        Write-Output 'You need to set the target syslog server and port; edit estreamer.conf '
        Write-Output 'and change $.handler.outputters[0].stream.uri'
        Write-Output ''
    }elseif ($choice -eq "3"){
        & $pybin $configure $configFilepath "--output=json"

        Write-Output 'If you wish to change where data is written to then edit estreamer.conf '
        Write-Output 'and change $.handler.outputters[0].stream.uri'
        Write-Output ''
    }else{
        Write-Output 'No changes made'
        Write-Output ''
        exit $EXIT_CODE_ERROR
    }
}

function init {
    $pythonVersion = $(& $pybin --version 2>&1).ToString()
    if ($pythonVersion -match "2.7.*"){
        Write-Output 'Python 2.7 is installed'
    }else {
        try {
            $getPythonPath = Read-Host "Where does your Python 2.7 live? Example - C:\Program Files\Python27\"
            $env:Path = $getPythonPath
            $pythonVersion = $(& $pybin --version 2>&1).ToString()
            if ($pythonVersion -match "2.7.*"){
                Write-Output 'Python 2.7 is installed'
            }
        }
        catch {
            Write-Output 'Python 2.7 is not available'
            Write-Output ''
            Write-Output 'It may be that you have both or neither python 2.x and 3.x installed but that your'
            Write-Output 'environment is not set up correctly. To see:'
            Write-Output ''
            Write-Output '    which python'
            Write-Output 'and'
            Write-Output '    whereis python'
            Write-Output ''
            Write-Output 'It is also possible that you have conflicting versions of python installed.'
            Write-Output 'Wherever possible, try to use a default system install located at /usr/bin/python'
            Write-Output ''
            exit $EXIT_CODE_ERROR
        }
    }
<#
    # This only seems necessary on Linux outside of Splunk
    $pyMaxUnicodeOk=`$pybin -c 'import sys; print(0x10000 < sys.maxunicode)'`
    if [ "$pyMaxUnicodeOk" = "False" ]
    then
        pyPath=`which python`

        Write-Output 'Incompatible build of python'
        Write-Output
        Write-Output 'eNcore requires the standard version of python built with PyUnicodeUCS4. You are'
        Write-Output 'seeing this error message because the currently executing version of python'
        Write-Output "($pyPath) is built with PyUnicodeUCS2."
        Write-Output
        Write-Output 'This is a known issue in certain cases when running as the splunk user (more here:'
        Write-Output 'https://answers.splunk.com/answers/327336/why-am-i-getting-importerror-undefined-symbol-pyun.html)'
        Write-Output
        Write-Output 'The solution is to create a new user with the standard python environment and run'
        Write-Output 'as that user.'
        Write-Output
        exit $EXIT_CODE_ERROR
    fi
#>
    if (!(Test-Path $configFilepath)){
        Write-Host "No $configFilepath found, creating that file by copying default.conf."
        Copy-Item default.conf $configFilepath
        setup
    }

    try{
        & $pybin $preflight $configFilepath
    }catch{
        exit $EXIT_CODE_ERROR
    }

    & $pybin $configure "--enabled=true" $configFilepath

    #$pidFile = & $pybin $configure "--print $pidFile"
    #$processpid = & $pybin $configure "--print $processpid"

    # Work out if we're running already
    $process = Get-WmiObject Win32_Process -Filter "name = '$pybin.exe'" | Select-Object CommandLine, handle
    $processpid = $process.handle
    $processCommandLine = $process.CommandLine
    if ($processpid = '-1' ){
        #Write-Output "Checking pid.... none found."
    }elseif ($process -eq 1){
        Remove-Item $pidFile
        $processpid = -1
        Write-Output "Stale pidFile ($processpid). Removing"
    }elseif ($processCommandLine -match "service.py"){
        $isRunning = 1
        Write-Output "$service $processCommandLine is running."
    }else{
        Write-Output $service "is not running"
        if (Test-Path -Path *.pid){
            Write-Output "Removing stale pidFile."
            Remove-Item *.pid
            $processpid = -1
        }
    }
}

function diagnostics {
    & $pybin $diagnostics $configFilepath
}

function foreground {
    & $pybin $service $configFilepath
}

function start_encore {
    if ($isRunning -eq 0){
        Write-Output -n "Starting \"$service\". "
        $service > $null
        Start-Sleep 1

        $processpid = $configure + " --print pid"
        Write-Output "Started. pid=$processpid"
    }else{
        Write-Output "$service is already running."
    }
}

function stop_encore {
    if ($isRunning -eq 0){
        Write-Output "Not running"
    }else {
        Write-Output "Found pid. Terminating \"$service\" ($processpid)"
        Stop-Process -Id $processpid

        # Wait for the process to finish
        do{
            # Do not redirect stdErr - Splunk no likey
            $process = Get-Process -Id $processpid

            if ($process -eq 1){
                break
                Start-Sleep -Seconds 1
            }else{
                $processpid = '-1'
                $isRunning = 0
                Start-Sleep -Seconds 1
            }
        }while($processpid -ne '-1')
    }
}

function restart_encore {
    stop_encore
    start_encore
}

function main {
    Write-Output "Usage: $prog {start | stop | restart | foreground | test | setup}"
    Write-Output ''
    Write-Output '    start:      starts eNcore as a background task'
    Write-Output '    stop:       stop the eNcore background task'
    Write-Output '    restart:    stop the eNcore background task'
    Write-Output '    foreground: runs eNcore in the foreground'
    Write-Output '    test:       runs a quick test to check connectivity'
    Write-Output '    setup:      change the output (splunk | cef | json)'
    Write-Output ''
    $usage = Read-Host "Enter an option."
    Switch ($usage)
    {
        start {start_encore}
        stop {stop_encore}
        restart {restart_encore}
        test {diagnostics}
        foreground {foreground}
        setup {setup}
    }
}

init
main

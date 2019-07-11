param([string]$1)

$SPLUNK_HOME= "C:\Program Files\splunk"
$proid='-1'
$configFilepath="estreamer.conf"
$pybin="python"
$basepath="$SPLUNK_HOME/etc/apps/TA-eStreamer/bin/encore/"
$basepathExists= Test-Path $basepath
$isRunning=0

# constants
$configure="$pybin ./estreamer/configure.py $configFilepath"
$diagnostics="$pybin ./estreamer/diagnostics.py $configFilepath"
$service="$pybin ./estreamer/service.py $configFilepath"
$preflight="$pybin ./estreamer/preflight.py $configFilepath"
$pidFile="encore.pid"

$EXIT_CODE_ERROR=0

function init() 
{ 
    # change pwd
    if ( $basepathExists -eq $True ) 
        { cd $basepath }
    
    else {
        echo "\"$basepath\" does not exist"
        exit $EXIT_CODE_ERROR
          }

    if ( ! ( Test-Path "$configFilepath" ) )
        { cp default.conf $configFilepath }
}

function preflight()
{
    $preflight --nostdin
    $ok=$?
    if ( $ok -eq $False )
    {
        exit $EXIT_CODE_ERROR
    } 
    $pidFile =`$configure --print pidFile`
    $proid = `$configure --print pid`

    # Work out if we're running already
    (Get-Process | Where-Object { $_.Name -eq $configFilepath }).Count -gt 0
    $process = $?

    if ($proid -eq '-1')
    {
        #echo "Checking pid... none found."
    }
    if ($process -eq $True)
    {
        rm $pidFile
        $proid = -1
    }
    Elseif ($process -eq $False)
    {
        $isRunning=1
    }

}
function diagnostics()
{
    $diagnostics
    #ready
}

 function foreground()
{
    $service
    #ready
}

function stop() 
{
    $isRunning = (Get-Process | Where-Object { $_.Name -eq $configFilepath }).Count -gt 0
    if ( $isRunning -eq $false )
    {
        echo "Splencore is not running"
    }
    else
    {
        echo "Splencore found pid. Terminating '$service' " 
        Stop-Process -processname $configFilepath

        while ( $True )
        {
            (Get-Process | Where-Object { $_.Name -eq $configFilepath }).Count -gt 0
            $process = $?
            
            if ( $process -eq $False)
            {
                break
            }

            sleep -s 0.5
        }
        $proid = -1
        sleep -s 1 
    }
}

function status()
{
    $configure --print splunkstatus
}

function clean()
{
    
}
function main($1){
    
    switch ($1)
    {
        test 
        {init; preflight; diagnostics}
        start
        {init; preflight; foreground}
        stop
        {init; preflight; stop}
        status
        {init; status}
        clean
        {init; clean}
        default
        {   
            echo "Usage:  { start | stop | test | status | clean }"
            echo "`n"
            echo '    start:      starts eNcore'
            echo '    stop:       stops eNcore'
            echo '    test:       runs a quick test to check connectivity'
            echo '    status:     returns the current status in a splunk way'
            echo '    clean:      removes data older than 12 hours'
            echo "`n"
            echo "`t$1"
            exit $EXIT_CODE_ERROR 
          }
    }
    
}

main $1
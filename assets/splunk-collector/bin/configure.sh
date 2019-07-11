#!/bin/sh
#SPLUNK_HOME=/opt/splunk

# Constants
pybin="python"
configFilepath="estreamer.conf"
basepath="$SPLUNK_HOME/etc/apps/$$APP_ID/bin/encore/"
configure="$pybin ./estreamer/configure.py $configFilepath"

if [ ! -d $basepath ]
then
    # echo "$basepath does not exist"
    exit
fi

cd $basepath

# This is called by configure_handler.py
echo `pwd`

# Ensure encore is stopped. It will restart if it needs to
../splencore.sh stop

if [ ! -e $configFilepath ]
then
    cp default.conf $configFilepath
fi

# If there isn't even a second parameter then output usage and stop
if [ -z "$2" ]
then
    echo "Usage: ./configure.sh enabled host port packets connections packets metadata doPkcs12 [ pkcs12password ]"
    exit
fi

# Read parameters into named variables
enabled=$1
host=$2
port=$3
packets=$4
connections=$5
metadata=$6
doPkcs12=$7
password=$8


echo "Configuring"
cmd="$configure --output=splunk --logstdout=true --logstderr=false --enabled=$enabled --conditions=splunk --host=$host --port=$port --connections=$connections --packets=$packets --metadata=$metadata --stream=relfile:///../../data/encore.{0}.log"
echo $cmd
$cmd


if [ "$doPkcs12" = "1" ]
then
    pkcs12file=`$configure --print pkcs12`
    if [ $? -ne 0 ]
    then
        # If there was an error, it will be in the return variable
        echo $pkcs12file
        exit
    fi

    privateKey=`$configure --print privateKey`
    publicKey=`$configure --print publicKey`

    if [ ! -e $pkcs12file ]
    then
        echo "PKCS12 file ($pkcs12file) does not exist"
        exit
    fi

    echo "Removing old keys" # ($privateKey and $publicKey)"
    rm -f $privateKey
    rm -f $publicKey

    echo "Recreating keys"
    openssl pkcs12 -in $pkcs12file -nocerts -nodes -out $privateKey -passin "pass:$password"
    if [ $? -ne 0 ]
    then
        exit
    fi

    openssl pkcs12 -in $pkcs12file -clcerts -nokeys -out $publicKey -passin "pass:$password"
fi

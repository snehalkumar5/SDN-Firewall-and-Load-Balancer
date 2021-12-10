#!/bin/bash


if [[ -z $1 ]];
then 
    echo "Please provide pox directory."
else
    sudo mn -c
    d="$1"
    cp ./firewall.py $d
    cp ./firewall-policies.csv $d
    cd $d
    sudo ./pox.py firewall
fi
#!/bin/bash
a=$(pwd)
#super.tab file address
#b="/etc/super.tab"
#echo "set super config"
#echo "startddosattack "$a/"maincontrol cp
#sendfileResult "$a/"serversendfile cp" >> $b

echo "start install"
echo "make source"
cd $a
make
make clean
echo ok


#!/bin/bash

echo running Karaf
screen -dmSL karaf /root/odl/main/bin/karaf

echo waiting for Karaf to boot
while [ true ]
do

    netstat -tulpn | grep 8101

    if [ $? -ne  1 ]
    then
        break
    fi

done

set -e

echo refreshing repo
sshpass -p karaf ssh -p 8101 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no karaf@localhost 'feature:repo-refresh'

echo installing packages
sshpass -p karaf ssh -p 8101 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no karaf@localhost 'feature:install odl-dluxapps-applications odl-restconf odl-dluxapps-applications odl-openflowplugin-southbound odl-vtn-manager-rest odl-l2switch-hosttracker'

# echo finishing Karaf
# sshpass -p karaf ssh -p 8101 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no karaf@localhost 'logout'

echo Done


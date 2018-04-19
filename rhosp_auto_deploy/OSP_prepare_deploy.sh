#!/bin/bash
##############################################################################
#  Copyright (c) 2018 Intel Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##############################################################################


DIR="$(cd "$(dirname "$0")" && pwd)"

set +e
source "$DIR/cloud.conf"

generate_instackenv() {
    echo "{"
    echo "  \"nodes\":["
    local macs=${#PROVISION_NIC_MAC[@]}

    for i in $(seq 1 ${#PROVISION_NIC_MAC[@]}); do
        ip=${NODES[i - 1]}
        mac=${PROVISION_NIC_MAC[i - 1]}
        roles=${PROFILE_ROLES[i - 1]}
        echo "      {"
        echo '          "mac":["'$mac'"],'
        echo '          "cpu":"4",'
        echo '          "memory":"6144",'
        echo '          "disk":"40",'
        echo '          "arch":"x86_64",'
        echo '          "pm_type":"pxe_ipmitool",'
        echo '          "pm_user":"admin",'
        echo '          "pm_password":"admin",'
        echo '          "pm_addr":"'$ip'",'
        echo '          "capabilities":"profile:'$roles','boot_option:local'"'
        if [ $i -lt $macs ]; then
            echo "      },"
        else
            echo "      }"
        fi
    done

    echo "  ]"
    echo "}"
}

echo "Removed /etc/profile.d/OSP_prepare_deploy.sh"
sudo rm -f /etc/profile.d/OSP_prepare_deploy.sh

echo "Unregistering System"
sudo subscription-manager unregister
sleep 3

echo "Registering System..."
sudo subscription-manager register --username=$RHNUSER --password=$RHNPASSWORD
sudo subscription-manager attach --pool=$POOLID
sudo subscription-manager repos --disable=*

echo "Enabling OSP $VERSION REPOS"

if [ $VERSION -eq 9 ]
then
	sudo subscription-manager repos --enable=rhel-7-server-rpms --enable=rhel-7-server-extras-rpms --enable=rhel-7-server-openstack-9-rpms --enable=rhel-7-server-openstack-9-director-rpms --enable=rhel-7-server-rh-common-rpms
elif [ $VERSION -eq 10 ]
then
	sudo subscription-manager repos --enable=rhel-7-server-rpms --enable=rhel-7-server-extras-rpms --enable=rhel-7-server-rh-common-rpms --enable=rhel-ha-for-rhel-7-server-rpms --enable=rhel-7-server-openstack-10-rpms
elif [ $VERSION -eq 11 ]
then
        sudo subscription-manager repos --enable=rhel-7-server-rpms --enable=rhel-7-server-extras-rpms --enable=rhel-7-server-rh-common-rpms --enable=rhel-ha-for-rhel-7-server-rpms --enable=rhel-7-server-openstack-11-rpms
else
	echo "Please specify RHEL OSP version..."
	exit 0
fi

echo "Generating instackenv.json"
generate_instackenv  > /home/stack/instackenv.json

echo "Creating Directories for Templates & Images"
mkdir -p ~/images
mkdir -p ~/templates

echo "Yum Updating system..."
sudo yum -y update
echo "finished yum update..." >> OSP_prepare_deploy.log

echo "Copy automation script OSP_deploy.sh to /etc/profile.d/."
sudo cp -f /root/OSP_deploy.sh /etc/profile.d/OSP_deploy.sh
sudo chown stack.stack /etc/profile.d/OSP_deploy.sh
echo "Reboot after yum update..." >> OSP_prepare_deploy.log
sleep 3 ; sudo reboot

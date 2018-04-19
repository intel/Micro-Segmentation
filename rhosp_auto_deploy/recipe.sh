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

# Auto login on all terminals
# source: https://www.centos.org/forums/viewtopic.php?t=48288
auto-login() {
rm -f /etc/systemd/system/getty.target.wants/getty@tty1.service

cp /lib/systemd/system/getty@.service /etc/systemd/system/getty@tty1.service

sed -i "s|ExecStart=-/sbin/agetty --noclear %I|ExecStart=-/sbin/agetty --autologin stack --noclear %I|g" \
/etc/systemd/system/getty@tty1.service

sed  '/\[Install\]/a ;Alias=getty@tty1.service' /etc/systemd/system/getty@tty1.service

ln -s /etc/systemd/system/getty@tty1.service /etc/systemd/system/getty.target.wants/getty@tty1.service
}

#CREATING A DIRECTOR INSTALLATION USER
echo "Creating user stack"
useradd stack
echo $PASSWD | passwd stack --stdin

#ADD AUTOLOGIN AS ROOT
auto-login

# Disable password requirements for this user "stack" when using sudo
echo "stack ALL=(root) NOPASSWD:ALL" | tee -a /etc/sudoers.d/stack
chmod 0440 /etc/sudoers.d/stack

echo -e "$MGMT_IP\t\t$FQDN\t$SHORT" >> /etc/hosts

hostnamectl set-hostname $FQDN
hostnamectl set-hostname --transient $FQDN

echo "Copy automation script OSP_prepare_deploy.sh to /etc/profile.d/."
cp /root/OSP_prepare_deploy.sh /etc/profile.d/OSP_prepare_deploy.sh
chown stack.stack /etc/profile.d/OSP_prepare_deploy.sh
cp /root/cloud.conf /home/stack/cloud.conf
chown -R stack.stack /home/stack/cloud.conf

if [ $VERSION -eq 9 ] && [ "$OVS_TYPE" == "vrs" ]
then
	echo "Copy Nuage image patching files..."
	mkdir -p /home/stack/image-patching
	sudo cp -fr /root/image-patching/. /home/stack/image-patching/.
	chown -R stack.stack /home/stack/image-patching /home/stack/image-patching/*
fi

echo "switch user account to stack"

sleep 3; su - stack


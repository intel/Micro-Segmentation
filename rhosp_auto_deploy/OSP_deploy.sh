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

#####
# Function to create undercloud.conf
#####
create_undercloud_conf() {
echo "Generating undercloud.conf"
cp /usr/share/instack-undercloud/undercloud.conf.sample $DIR/undercloud.conf
sed -i "s|#image_path = \.|image_path = $DIR/images|g" $DIR/undercloud.conf
sed -i "s|#undercloud_hostname = <None>|undercloud_hostname = $FQDN|g" $DIR/undercloud.conf
sed -i "s|#local_ip = 192.0.2.1/24|local_ip = $LOCAL_IP|g" $DIR/undercloud.conf
sed -i "s|#network_gateway = 192.0.2.1|network_gateway = $NETWORK_GATEWAY|g" $DIR/undercloud.conf
sed -i "s|#undercloud_public_vip = 192.0.2.2|undercloud_public_vip = $UNDERCLOUD_PUBLIC_VIP|g" $DIR/undercloud.conf
sed -i "s|#undercloud_admin_vip = 192.0.2.3|undercloud_admin_vip = $UNDERCLOUD_ADMIN_VIP|g" $DIR/undercloud.conf
sed -i "s|#local_interface = eth1|local_interface = $LOCAL_IFACE|g" $DIR/undercloud.conf
sed -i "s|#network_cidr = 192.0.2.0/24|network_cidr = $NETWORK_CIDR|g" $DIR/undercloud.conf
sed -i "s|#masquerade_network = 192.0.2.0/24|masquerade_network = $MASQUERADE_NETWORK|g" $DIR/undercloud.conf
sed -i "s|#dhcp_start = 192.0.2.5|dhcp_start = $DHCP_START|g" $DIR/undercloud.conf
sed -i "s|#dhcp_end = 192.0.2.24|dhcp_end = $DHCP_END|g" $DIR/undercloud.conf
sed -i "s|#inspection_interface = br-ctlplane|inspection_interface = $INSPECTION_INTERFACE|g" $DIR/undercloud.conf
sed -i "s|#inspection_iprange = 192.0.2.100,192.0.2.120|inspection_iprange = $INSPECTION_IP_START,$INSPECTION_IP_END|g" $DIR/undercloud.conf
sed -i "s|#inspection_extras = true|inspection_extras = $INSPECTION_EXTRAS_BOOL|g" $DIR/undercloud.conf
sed -i "s|#inspection_runbench = false|inspection_runbench = $INSPECTION_RUNBENCH_BOOL|g" $DIR/undercloud.conf
sed -i "s|#undercloud_debug = true|undercloud_debug = $UNDERCLOUD_DEBUG_BOOL|g" $DIR/undercloud.conf
}

#####
# Function to change overcloud image root password
#####
change_overcloud_qcow2_password() {
virt-customize -a '/home/stack/images/overcloud-full.qcow2' --root-password password:$PASSWD 
echo "Root password changed..." >> OSP_deploy.log
}

#####
# Function to add files based on the version
#####
patch_undercloud_files() {
sudo cp -fr /home/stack/image-patching/diff_OSPD10_5.2.0-15 /usr/share/
cd /usr/share/
sudo patch -p0 -N < diff_OSPD10_5.2.0-15
cd /home/stack
}

#####
# Function to generate CMS ID and put it into yaml file
#####
generate_cmsid() {        
cd /home/stack/generate_cms_id
python configure_vsd_cms_id.py --server $NeutronNuageVSDIp --serverauth $NeutronNuageVSDUsername:$NeutronNuageVSDPassword --organization $NeutronNuageVSDOrganization --auth_resource /me --serverssl True --base_uri /nuage/api/$NeutronNuageBaseURIVersion
id=`cat cms_id.txt`
sed -i "s|NeutronNuageCMSId: ''|NeutronNuageCMSId: '"$id"'|g" /home/stack/templates/network-environment-nuage.yaml
cd /home/stack
}

#####
# Function to get disks serial number and set it to nodes
#####
set_disks_serial() {
for node in $(openstack baremetal node list | awk '!/UUID/ {print $2}'); do echo "NODE: $node" ; openstack baremetal introspection data save $node | jq '.inventory.disks' ; echo "-----" ; done
 
echo "Updating the disk information for each node"
for node_uuid in $(openstack baremetal node list | awk '!/UUID/ {print $2}'); do
    first_serial=$(openstack baremetal introspection data save $node_uuid | jq '.inventory.disks[0].serial' | sed -r 's/"(.*)"/\1/g' | sed -e 's/\(.*\)/\L\1/')
    echo $first_serial
    openstack baremetal node set --property root_device='{"serial": "'$first_serial'"}' $node_uuid
done
}

## Main ##
sudo rm -f /etc/profile.d/OSP_deploy.sh
echo "edit getty@tty1.service this file"
sudo sed -i "s|ExecStart=-/sbin/agetty --autologin stack --noclear %I|ExecStart=-/sbin/agetty --noclear %I|g" \
/etc/systemd/system/getty@tty1.service

sudo yum install -y python-tripleoclient nano wget

create_undercloud_conf

echo "Launching: openstack undercloud install"
openstack undercloud install

source /home/stack/stackrc

## Copying Overcloud heat templates
sudo cp -fr /root/templates/. /home/stack/templates/.
sudo chown -R stack.stack /home/stack/templates /home/stack/templates/*

cd /home/stack/images
echo 'Installing director images and VIRT-CUSTOMIZE To the Director'
sudo yum -y install rhosp-director-images rhosp-director-images-ipa libguestfs-tools

echo 'Extracting downloaded images'
for i in /usr/share/rhosp-director-images/overcloud-full-latest-10.0.tar /usr/share/rhosp-director-images/ironic-python-agent-latest-10.0.tar; do tar -xvf $i; done

## Nuage VRS deployment
if [ "$OVS_TYPE" == "vrs" ]
then
	## Copy all nneded resources for nuage deployment
	mkdir /home/stack/generate_cms_id
	sudo cp -frv /root/generate_cms_id/. /home/stack/generate_cms_id/.
	sudo chown -R stack.stack /home/stack/generate_cms_id /home/stack/generate_cms_id/*
	mkdir /home/stack/image-patching
	sudo cp -frv /root/image-patching/. /home/stack/image-patching/.
	sudo chown -R stack.stack /home/stack/image-patching /home/stack/image-patching/*

	## Patching overcloud-full.qcow2 image for VRS or uploading already patched image
	if [ "$NuagePrebuiltImage" == "true" ]
	then
		sudo cp -fv /root/images/overcloud-full.qcow2 /home/stack/images/	
		sudo chown stack:stack /home/stack/images/overcloud-full.qcow2
	else
		cd /home/stack/image-patching/
		source nuage_overcloud_full_patch.sh --RhelUserName=$RHNUSER --RhelPassword='$RHNPASSWORD' --RepoName=$NuageRepoName --RepoBaseUrl=$NuageRepoUrl --RhelPool=$POOLID --ImageName='/home/stack/images/overcloud-full.qcow2' --Version=$VERSION
	fi
	cd /home/stack

	## Generate CMS ID and put it into yaml template if VRS is used
	generate_cmsid

	## Patching Undercloud heat templates
	patch_undercloud_files
fi

## Setting root password
echo "Setting Overcloud Image root Password"
export LIBGUESTFS_BACKEND=direct
change_overcloud_qcow2_password

echo 'Importing images into the director'
openstack overcloud image upload --image-path /home/stack/images/

echo "Setting a nameserver on the undercloud's neutron subnet"
neutron subnet-update "$(neutron subnet-list -f value -F id | head -n 1)" --dns-nameserver 8.8.8.8

echo "Registering nodes for overcloud"
openstack baremetal import --json /home/stack/instackenv.json

echo "Introspecting hardware"
for node in $(openstack baremetal node list --fields uuid -f value) ; do openstack baremetal node manage $node ; done
openstack overcloud node introspect --all-manageable

## Pendrive / small drive problem elimination + automatic "wwn" identifier selection
if [ "$SelectLargestDrive" == "true" ]
then
	openstack overcloud node configure --all-manageable --root-device=largest
else
	set_disks_serial
fi
for node in $(openstack baremetal node list --fields uuid -f value) ; do openstack baremetal node provide $node ; done

openstack overcloud profiles list 

echo 'Starting overcloud deploy'
cd /home/stack

if [ "$OVS_TYPE" == "ovs" ]
then
        openstack overcloud deploy --templates \
        -e /usr/share/openstack-tripleo-heat-templates/environments/network-isolation.yaml \
        -e ~/templates/network-environment.yaml \
        --timeout 150 \
        --neutron-network-type vxlan \
        --neutron-tunnel-types vxlan \
        --log-file overcloud_deploy.log
elif [ "$OVS_TYPE" == "vrs" ]
then 
	openstack overcloud deploy --templates \
	-e /usr/share/openstack-tripleo-heat-templates/environments/network-isolation.yaml \
	-e ~/templates/network-environment-nuage.yaml \
	--timeout 150 \
	--neutron-network-type vxlan \
	--neutron-tunnel-types vxlan \
	--log-file overcloud_deploy.log
else
	echo "$OVS_TYPE Supported TBD..."
fi

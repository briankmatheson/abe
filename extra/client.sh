#!/bin/bash -xe
#
# Simple ABE Client example

host=brick
url=http://$host/configure

sudo sh -c 'apt update && apt -y install curl nvme-cli nfs-kernel-server' || exit 1
sudo modprobe nvmet

response=`curl --silent "$VM_URL"`
message=`echo $response | jq -r .message`

while read line; do
    result=`echo $line | bash`
    id=`echo $line | awk '{print $NF}'`
    device=`sudo /sbin/blkid -t PARTLABEL=$id | awk -F: '{print $1}'`
    sudo mkdir -p /export/$id
    sudo mount $device /export/$id
    echo "/export/$id		*(rw,sync,fsid=0,no_root_squash,no_subtree_check)" | sudo tee -a /etc/exports
    sudo exportfs -a
done <<EOF
$message
EOF


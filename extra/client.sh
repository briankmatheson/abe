#!/bin/bash -xe
#
# Simple ABE Client example

host=brick

if [ -n "$1" ]; then
    id=$1
elif [ -f ~/.abe ]; then
    read id < ~/.abe
fi

if [ -n "$id" ]; then
    url=http://$host/id/$id
else
    url=http://$host/configure
    sh -c 'apt update && apt -y install curl jq nvme-cli nfs-kernel-server' || exit 1
fi

modprobe nvmet

response=`curl --silent "$url"`
message=`echo $response | jq -r .message`

while read line; do
    result=`echo $line | bash`
    id=`echo $line | awk '{print $NF}'`
    device=`/sbin/blkid -t PARTLABEL=$id | awk -F: '{print $1}'`
    mkdir -p /export/nfs && \
    mount $device /export/nfs && \
    echo "/export/nfs		*(rw,sync,no_root_squash,no_subtree_check)" | tee /etc/exports
    exportfs -a
    echo $id | tee ~/.abe
done <<EOF
$message
EOF


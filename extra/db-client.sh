#!/bin/bash -xe
#
# ABE Postgres example

if [ $USER != 'root' ]; then
    echo gotta be root
    exit 4
fi


install(){
    sh -c 'apt update && apt -y install sudo curl jq nvme-cli nfs-kernel-server mdadm' || exit 1
}



if [ -s ~/.abe ]; then
    one=`awk '{print $1}' ~/.abe`
    two=`awk '{print $2}' ~/.abe`
    three=`awk '{print $3}' ~/.abe`
    echo connect to $one $two $three
else
    touch ~/.abe
fi
if [ -z "$one" -o -z "$two" -o -z "$three" ]; then
    if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
	echo Need to supply three ABE hosts to attach to on first run.
	exit 2
    else
	install
	for server in $1 $2 $3; do
	    url=http://$server/configure
	    response=`curl --silent "$url"`
	    message=`echo $response | jq -r .message`
	    port=`echo $response | jq -r .port`
	    id=`echo $response | jq -r .id`
	    #result=`sudo nvme connect -a $server -t tcp -s $port -n $id`
	    echo -n ${1}:${port}:${id} ' ' >> ~/.abe
        done
        echo >> ~/.abe
        
    fi
fi

if [ -s ~/.abe ]; then
    one=`awk '{print $1}' ~/.abe`
    two=`awk '{print $2}' ~/.abe`
    three=`awk '{print $3}' ~/.abe`
    if [ -z "$one" -o -z "$two" -o -z "$three" ]; then
        echo trouble at the mill
        exit 3
    fi
    modprobe nvmet
    md_devs=""
    for drive_id in $one $two $three; do
	server_address=`echo $drive_id | tr : ' ' | awk '{print $1}'`
	port=`echo $drive_id | tr : ' ' | awk '{print $2}'`
	block_id=`echo $drive_id | tr : ' ' | awk '{print $3}'`
	result=`sudo nvme connect -a $server_address -t tcp -s $port -n $block_id`
        device=`/sbin/blkid -t PARTLABEL=$block_id | awk -F: '{print $1}'`
 	md_devs="$device $md_devs"
    done
    mdadm --create /dev/md0 --level=1 --raid-devices=3 $md_devs
    mkfs.ext4 /dev/md0
    mkdir -p /var/lib/postrgresql
    mount /dev/md0 /var/lib/postgresql
    apt install -y postgresql
else
    exit 1
fi


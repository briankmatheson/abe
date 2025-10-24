#!/bin/bash -xe
#
# ABE Postgres example

install(){
    sh -c 'apt update && apt -y install curl jq nvme-cli nfs-kernel-server' || exit 1
}

attach(){
    md_devs=""
    for drive_id in $1 $2 $3; do
	echo $drive_id | tr : ' ' | read server_address block_id
	url="http://$server_address/$block_id"
	response=`curl --silent "$url"`
	message=`echo $response | jq -r .message`
	
	while read line; do
	    result=`echo $line | bash`
	    id=`echo $line | awk '{print $NF}'`
	    device=`/sbin/blkid -t PARTLABEL=$id | awk -F: '{print $1}'`
 	    md_devs="$device $devices"
	done <<EOF
$message     
EOF
    done	     
}	     
 
if [ -f ~/.abe ]; then
    cat ~/.abe | read one two three
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
	    echo -n ${1}:${id} ' ' >> ~/.abe
	done	    	
    fi 
    while read one two three; do
	modprobe nvmet
	attach $one $two $three
	done < ~/.abe
fi

mdadm --create /dev/md0 --level=1 --raid-devices=3 $md_devs
mount /dev/md0 /var/lib/postgresql
apt install -y postgresql

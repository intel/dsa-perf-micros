#!/bin/bash

# see README.md for usage

assign_dev() {
	[  -d /sys/bus/pci/devices/$dev/driver/ ] && echo $dev > /sys/bus/pci/devices/$dev/driver/unbind
	device=`cat /sys/bus/pci/devices/$dev/device`
	vendor=`cat /sys/bus/pci/devices/$dev/vendor`
	echo $vendor $device > /sys/bus/pci/drivers/$driver/new_id 2>1  | grep -v exists
	echo $dev > /sys/bus/pci/drivers/$driver/bind
	echo $dev bound to $(basename $(readlink /sys/bus/pci/devices/$dev/driver))
}

driver=$1
shift

modprobe $driver 2>/dev/null

for dev in $@; do
	dev=$(echo 0000:$dev)
	assign_dev
done

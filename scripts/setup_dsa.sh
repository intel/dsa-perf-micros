#!/bin/bash

# TODO: use accel-config to replace instances of `cat sysfs path`

num_dsa=`ls /sys/bus/dsa/devices/  | grep dsa | wc -l`


script=`basename $0`

init_common() {
	NUM_ENGINES=`cat /sys/bus/dsa/devices/$dname/max_engines`
	NUM_WQS=`cat /sys/bus/dsa/devices/$dname/max_work_queues`
	DSA_CONFIG_PATH=/sys/bus/dsa/devices
}

reset_config() {
	local did=$1

	for ((i = 0; i < $NUM_ENGINES ; i++ ))
	do
		accel-config config-engine $dname/engine$did.$i --group-id=-1
	done
	for ((i = 0; i < $NUM_WQS ; i++ ))
	do
		accel-config config-wq $dname/wq$did.$i --wq-size=0
	done
}

assign_free_engine() {

	local did=$1
	local gid=$2

	for ((i = 0; i < $NUM_ENGINES ; i++ ))
	do
		if (( `cat $DSA_CONFIG_PATH/$dname/engine$did.$i/group_id` == -1 ))
		then
			accel-config config-engine $dname/engine$did.$i --group-id=$gid
			return 0
		fi
	done

	echo "Unable to find free engine"
	exit 1
}

usage() {
    cat <<HELP_USAGE

    usage: $script [-d device (dsa0/iax1/..) ] [-w num wqs] [-q wq id] [-m wq mode (d or s)] [-s wq sz] [-e num eng] [-g grpID] [-b bind or not? (0 or 1)]
		configures wqs
	   E.g. Setup dsa0 with 1 group/1DWQ/1eng :
			 $script -d dsa0 -w1 -md -e1
		Setup dsa0 with 2 groups: grp1/1DWQ-64qd/1eng, grp2/1SWQ-64qd/1eng
			 $script -d dsa0 -g0 -w1 -q0 -s64 -md -e1 -b0
			 $script -d dsa0 -g1 -w1 -q1 -s64 -ms -e1 -b0
			 $script -d dsa0 -b1

	   $script [-d device]
		disables device and resets config

	   $script <config file path>
HELP_USAGE
	exit 0
}

unbind() {

	case $1 in

	0)
		for ((i = 0; i < $NUM_WQS ; i++ ))
		do
			accel-config disable-wq $dname/wq$did.$i 2>/dev/null && echo disabled $dname/wq$did.$i
		done

		accel-config disable-device $dname 2>/dev/null && echo disabled $dname
		reset_config $did

		;;

	1)

		d=$(echo $dname | tr -cd '[[:digit:]]')

		for i in {0..7}
		do
			[[ `cat /sys/bus/dsa/devices/$dname/wq$d\.$i/state` == "enabled" ]] && accel-config disable-wq $dname/wq$d\.$i
		done

		[[ `cat /sys/bus/dsa/devices/$dname/state` == "enabled" ]] && accel-config disable-device $dname
		reset_config $d

		;;

	*)
		echo "unknown"
		;;
	esac
}

configure() {

	case $1 in

	0)
		for ((i = 0; i < $num_eng ; i++ ))
		do
			assign_free_engine $did $grp_id
		done

		q=$qid
		[[ "$q" == "-1" ]] && q=0

		for ((i = 0; i < $num_wq ; i++, q++ ))
		do
			accel-config config-wq $dname/wq$did.$q --group-id=$grp_id --block-on-fault=0 --mode=$mode --priority=10 --wq-size=$size --type=user --name=app$i --driver-name=user
			[[ $mode == shared ]] && accel-config config-wq $dname/wq$did.$q --threshold=$size
		done
		;;

	1)
		accel-config load-config -c $config
		;;

	*)
		echo "Unknown"
		;;
	esac
}

bind() {
	# start devices
	accel-config enable-device  $dname
	d=$(echo $dname | tr -cd '[[:digit:]]')

	for i in {0..7}
	do
		[[ `cat /sys/bus/dsa/devices/$dname/wq$d\.$i/size` -ne "0" ]] && accel-config enable-wq $dname/wq$d\.$i
	done
}

do_config_file() {

	config=$1
	dname=`cat $config  | grep \"dev\":\"dsa  | cut -f2 -d: | cut -f1 -d, | sed -e s/\"//g`
	init_common

	unbind 1
	configure 1
	bind

	exit 0
}

do_options() {
	num_wq=0
	num_eng=4
	grp_id=0
	wsz=0
	qid=-1
	do_bind=-1
	do_cfg=-1
	mode=d

	if [[ ! $@ =~ ^\-.+ ]]
	then
	usage
	fi

	while getopts d:w:m:e:g:s:b:c:q: flag
	do
	    case "${flag}" in
		d)
			dname=${OPTARG}
			did=`echo $dname | awk '{print substr($0,4)}'`
			;;
		w)
			num_wq=${OPTARG}
			;;
		e)
			num_eng=${OPTARG}
			;;
		g)
			grp_id=${OPTARG}
			;;
		m)
			mode=${OPTARG}
			;;
		s)
			wsz=${OPTARG}
			;;
		b)
			do_bind=${OPTARG}
			;;
		c)
			do_cfg=${OPTARG}
			;;
		q)
			qid=${OPTARG}
			;;
		:)
			echo 1
			usage >&2
			;;
		*)
			echo 2
			usage >&2
			;;
	    esac
	done

	init_common

	if (( $qid >= $NUM_WQS ))
	then
		echo "Queue num should be less than $NUM_WQS" && exit 1
	fi

	if (( $qid != -1 && wsz == 0 ))
	then
		echo "Missing WQ size"
		usage && exit
	fi

	if (( $qid != -1 ))
	then
		num_wq=1
	fi

	if (( $num_wq != 0 ))
	then
		do_cfg=1
	fi

	if (( $do_cfg == 1 && $do_bind == -1 ))
	then
		unbind 0
		do_bind=1
	fi

	[ -d /sys/bus/dsa/devices/$dname ] || { echo "Invalid dev name $dname" && exit 1; }

	if (( $do_bind != -1 || $do_cfg != -1  ))
	then
		[[ $mode == "d" ]] && mode=dedicated
		[[ $mode == "s" ]] && mode=shared

		if (( $wsz == 0 && num_wq != 0 ))
		then
			wq_size=`cat /sys/bus/dsa/devices/$dname/max_work_queues_size`
			size=$(( wq_size / num_wq ))
		else
			size=$wsz
		fi

		[[ "$do_cfg" == "1" ]] && configure 0
		[[ "$do_bind" == "1" ]] && bind
	else
		unbind 0
	fi

	exit 0
}

if [ $# -eq "0" ]
then
	usage
elif [ -f "$1" ]
then
	do_config_file $1
else
	do_options $@
fi

#!/bin/bash

#
# run_bw_lat <micros dir path> <output file path/prefix> <bw or lat> <ats_lat=on|off> <DSA op>
#	     <core to run on> <mode (dpdk|user)> <dev> <wq type> <batch=yes|no> <queue depth> <miscF>
# summary will be written to <file path>_summary.txt"
#	$1 : path to dsa_perf_micros directory
#	$2 : path to where logs and result summary are written to
#	$3 : test mode: select between latency or bandwidth runs (this changes certain
#	     test params like number of iterations, num descriptors, test flags etc.
#	$4 : on/off - In latency mode, this selects parameters for ATS measurements
#	$5 : DSA opcode to run (combination of opcode and mode controls some flags)
#	$6 : core to run on
#	$7 : select between dpdk or idxd driver mode
#	$8 : bus number of DSA device to use (e.g. e7)
#	$9 : wq type (0=>DWQ, 1=>SWQ)
#	$10: batch: yes or no
#	$11: queue depth
#	$12: num threads
#	$13: misc flags (e.g. -l0=>2MB, -l1=>1G)
#

if (( $# < 12 )); then
	echo "Insufficient params specified: expecting 12 or 13, received $#";
	exit;
fi

size2mb=$(( 2 * 1024 * 1024 ))
size1g=$(( 1 * 1024 * 1024 * 1024 ))
size4k=$(( 4 * 1024 ))

init_devtlb_miss_stride() {
	local pg_sz;

	p1g=`echo $misc_flags | grep l1`
	p2m=`echo $misc_flags | grep l0`
	if [ -z "$p1g" ] && [[ -z "$p2m" ]]; then
		pg_sz=$size4k
	fi

	if [ -z "$p1g" ]; then
			pg_sz=$size2mb
	else
			pg_sz=$size1g
	fi

	stride="-t$(( ((x - 1 )/pg_sz + 1) * pg_sz ))"
}

### Enable cpu/platform performance settings
# Energy perf bias setting
x86_energy_perf_policy performance

# set scaling governor to perf mode
cpupower frequency-set -g performance
# disable Turbo
#echo 0 > /sys/devices/system/cpu/cpufreq/boost
for x in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
	echo performance > $x
done;
echo 0 > /proc/sys/kernel/numa_balancing

binpref=$1
pref=$2;
mode=$3;
atslat=$4;
op=$5;
core=$6;
startcore=$6;
usersvm=$7;
dev=$8;
wq_type=$9;
batch=${10};
qd=${11};
numt=${12};
if (( $# >= 13 )); then
	for (( x=13; $x <= $#; x=( $x + 1 ) )); do
		pgsz_flg="$pgsz_flg "`eval echo \$\{$x\}`;
	done;
else
	pgsz_flg="";
fi

loop=20;
flags1="-c";
fcnt=1;
dfield=9;
maxsz=9000000;
#maxsz=9000;
maxcores=`egrep "processor|cpu cores" /proc/cpuinfo|egrep -A1 ": 0"|grep cores|cut -d ':' -f2`;
maxcores=`expr $maxcores - $numt`;
skip_pcnt=10;

misc_flg="";
atsflags_cnt=0;
#tmpf=${pref}_${usersvm}_${mode}_op${op}_batch${batch}_tmpfile;
tmpf=${pref}_${usersvm}_${mode}_tmpfile;
sumf=${pref}_${usersvm}_${mode}_op${op}_batch${batch}_summary.txt;
outf=${pref}_${usersvm}_${mode}_op${op}_batch${batch}.out;

for x in /sys/bus/dsa/devices/dsa[0-9]*; do
	echo $x/wqN.0 : `cat $x/wq*.0/state` >> $outf;
	echo $x/wqN.0 : `cat $x/wq*.0/mode` >> $outf;
	echo $x/wqN.0 : `cat $x/wq*.0/size` >> $outf;
	echo $x/groupN.0 : `cat $x/group*.0/engines` >> $outf;
	echo $x/groupN.0 : `cat $x/group*.0/work_queues` >> $outf;
	echo >> $outf;
done
echo >> $outf;

devn=`echo $dev |cut -d ':' -f1`;

if [ $mode = "lat" ]; then
	qd=1;
	iter=1;
	ndesc=1;
	startsz=64;
	misc_flg="${pgsz_flg}";
	atsmode=`lspci -s ${devn}:1.0 -vv|grep ATSCtl | tr '[:blank:]' ' ' |cut -d ':' -f 2|cut -d ' ' -f2 | cut -d ',' -f1`;
	cplloopflags1="-x80";
	cpllooptstr1="cpl_pause"; #cpl pause
	cplloopflags2=" ";
	cpllooptstr2="cpl_busypoll"; #cpl busy
	cplloopflags3="-x100";
	cpllooptstr3="cpl_umwait"; #cpl uwmwait
	cplloopflags_cnt=3;

	atsflags1=" ";
	lattstr1="-iotlbM"; # iotlbM using single desc, 1 iter
	atsflags2="-i100";
	lattstr2="-iotlbH";  # iotlbH by warming up iommu caches only (evicts devtlb)
	atsflags3="-W99  -i100";
	lattstr3="-devtlbH"; #devtlbH by warming up devtlb

	if [ $atsmode = "Enable+" ]; then
		if [ $atslat = "on" ]; then
			atsflags_cnt=3;
			maxsz=600000;
		fi
	else
		if [ $atslat = "on" ]; then
			echo "Warning: Device has ATS disabled; will be unable to perform ATS latency measrement";
			# skip the device tlb hit case since there is no ATS
			atsflags_cnt=2;
			maxsz=600000;
		fi
	fi
else
	iter=10000;
	ndesc=$qd;
	loop=10;
	dfield=5;
	# use diff portal addr if dwq
	if (( $wq_type == 0 )); then
		misc_flg="-c ${pgsz_flg}";
	else # for swq, no need to vary portal addr since 1 thread can only do 1 at a time (app picks a diff CL addr per thread)
		misc_flg="${pgsz_flg}";
	fi
	startsz=256;
	cplloopflags1="-x80";
	cpllooptstr1="cpl_pause"; #cpl pause
	cplloopflags_cnt=1;
fi

bin="${binpref}/src/dsa_perf_micros ";
if [ $usersvm = "dpdk" ]; then
	bin="$(echo $bin) -u ";
	drv=`lspci -s ${devn}:1.0 -vv|grep -i "in use"| tr '[:blank:]' ' ' |cut -d ':' -f 2|cut -d ' ' -f2 `;
	if [ $drv = "uio_pci_generic" ]; then
		echo "uio driver loaded; need FLR" >> $outf;
		flrCmd="yes";
	else
		flrCmd="no";
	fi
else
	flrCmd="no";
fi

if (( $op == 6 || $op == 5 || $op == 16 )); then
	if [ $atslat = "on" ]; then
		#1. src clflushed
		s=1;
		for (( j=1; $j <= $atsflags_cnt; j=( $j + 1 ) )); do
			tmp="echo -zF \$atsflags$j";
			tmp="flags$j=\"`eval $tmp`\"";
			eval $tmp;
			tmp="echo -sF \$lattstr$j";
			tmp="tstr$j=\"`eval $tmp`\"";
			eval $tmp;
		done;
		fcnt=$atsflags_cnt;
	else
		s=1;
		#1. src clflushed
		flags1="-zF "; tstr1="-sF";
		#2. src cldemoted
		flags2="-zD "; tstr2="-sD";
		#3. src prefetched
		flags3="-zP "; tstr3="-sP";
		fcnt=2;
	fi
elif (( $op == 3 || $op == 17 || $op == 9 )); then
	if [ $atslat = "on" ]; then
		#1. src clflushed
		for (( j=1; $j <= $atsflags_cnt; j=( $j + 1 ) )); do
			tmp="echo -zF,F -f \$atsflags$j";
			tmp="flags$j=\"`eval $tmp`\"";
			eval $tmp;
			tmp="echo -sFdF \$lattstr$j";
			tmp="tstr$j=\"`eval $tmp`\"";
			eval $tmp;
		done;
		fcnt=$atsflags_cnt;
	else
		#1. src clflushed - dest clflushed
		flags1="-zF,F -f "; tstr1="-sFdF_walloc";
		#2. src cldemoted - dest clflushed
		flags2="-zD,F -f "; tstr2="-sDdF_walloc";
		#3. src prefetched - dest clflushed
		flags3="-zP,F -f  "; tstr3="-sPdF_walloc";
		#4. src clflushed - dest cldemoted
		flags4="-zF,D -f ";  tstr4="-sFdD_walloc";
		#5. src clflushed - dest prefetched
		flags5="-zF,P -f  ";  tstr5="-sFdP_walloc";
		#6. src cldemoted - dest cldemoted
		flags6="-zD,D -f  "; tstr6="-sDdD_walloc";
		#7. src cldemoted - dest prefetched
		flags7="-zD,P -f "; tstr7="-sDdP_walloc";
		#8. src prefetched - dest cldemoted
		flags8="-zP,D -f "; tstr8="-sPdD_walloc";
		#9. src prefetched - dest prefetched
		flags9="-zP,P -f  "; tstr9="-sPdP_walloc";

		#1. src clflushed - dest clflushed
		flags10="-zF,F "; tstr10="-sFdF_noalloc";
		#2. src cldemoted - dest clflushed
		flags11="-zD,F "; tstr11="-sDdF_noalloc";
		#3. src prefetched - dest clflushed
		flags12="-zP,F "; tstr12="-sPdF_noalloc";
		#4. src clflushed - dest cldemoted
		flags13="-zF,D ";  tstr13="-sFdD_noalloc";
		#5. src clflushed - dest prefetched
		flags14="-zF,P ";  tstr14="-sFdP_noalloc";
		#6. src cldemoted - dest cldemoted
		flags15="-zD,D "; tstr15="-sDdD_noalloc";
		#7. src cldemoted - dest prefetched
		flags16="-zD,P "; tstr16="-sDdP_noalloc";
		#8. src prefetched - dest cldemoted
		flags17="-zP,D "; tstr17="-sPdD_noalloc";
		#9. src prefetched - dest prefetched
		flags18="-zP,P "; tstr18="-sPdP_noalloc";
		fcnt=18;
	fi
elif (( $op == 4 )); then
	if [ $atslat = "on" ]; then
		#1. src clflushed
		#flags1="-zF -f $atsflags1"; tstr1="-dF -iotlbM";
		#flags2="-zF -f $atsflags2"; tstr2="-dF -iotlbH";
		#flags3="-zF -f $atsflags3"; tstr3="-dF -devtlbH";
		for (( j=1; $j <= $atsflags_cnt; j=( $j + 1 ) )); do
			tmp="echo -zF -f \$atsflags$j";
			tmp="flags$j=\"`eval $tmp`\"";
			eval $tmp;
			tmp="echo -dF \$lattstr$j";
			tmp="tstr$j=\"`eval $tmp`\"";
			eval $tmp;
		done;
		fcnt=$atsflags_cnt;
	else
		#1. destination clflushed and write-allocate to DDIO
		flags1="-zF -f "; tstr1="-dF_walloc";
		#2. destination cldemoted and write-allocate to DDIO
		flags2="-zD -f "; tstr2="-dD_walloc";
		#3. destination prefetched and write-allocate to DDIO
		flags3="-zP -f "; tstr3="-dP_walloc";

		#1. destination clflushed and no-write-allocate to DDIO
		flags4="-zF "; tstr4="-dF_noalloc";
		#2. destination cldemoted and no-write-allocate to DDIO
		flags5="-zD "; tstr5="-dD_noalloc";
		#3. destination prefetched and no-write-allocate to DDIO
		flags6="-zP "; tstr6="-dP_noalloc";
		fcnt=6;
	fi
elif (( $op == 32 )); then
	if [ $atslat = "on" ]; then
		#1. clflush
		#flags1="-zF  $atsflags1"; tstr1="-dF -iotlbM";
		#flags2="-zF  $atsflags2"; tstr2="-dF -iotlbH";
		#flags3="-zF  $atsflags3"; tstr3="-dF -devtlbH";
		for (( j=1; $j <= $atsflags_cnt; j=( $j + 1 ) )); do
			tmp="echo -zF \$atsflags$j";
			tmp="flags$j=\"`eval $tmp`\"";
			eval $tmp;
			tmp="echo -dF \$lattstr$j";
			tmp="tstr$j=\"`eval $tmp`\"";
			eval $tmp;
		done;
		fcnt=$atsflags_cnt;
	else
		#1. destination clflushed
		flags1="-zF "; tstr1="-dF";
		#2. destination clwb
		flags2="-zD -f "; tstr2="-dW";
		fcnt=2;
	fi
elif (( $op == 0 )); then
	# overriding default iter count set above for nop
	if [ $atslat = "on" ]; then
		#flags1=$atsflags1; tstr1="-iommuM_devtlbM";
		#flags2=$atsflags2; tstr2="-iommuH_devtlbM";
		#flags3=$atsflags3; tstr3="-devtlbH";
		for (( j=1; $j <= $atsflags_cnt; j=( $j + 1 ) )); do
			tmp="echo \$atsflags$j";
			tmp="flags$j=\"`eval $tmp`\"";
			eval $tmp;
			tmp="echo \$lattstr$j";
			tmp="tstr$j=\"`eval $tmp`\"";
			eval $tmp;
		done;
		fcnt=$atsflags_cnt;
	else
		flags1=" ";
		fcnt=1;
	fi
	dfield=5;
	maxsz=100;
fi

if [ $batch = "yes" ]; then
	fcnt=1;
	startb=2;
	maxb=160;
	mulb=2;
	iter=1000;
	maxsz=33000;
	scaleb=$qd;
else
	startb=1;
	maxb=2;
	mulb=2;
	#fcnt=1;
	scaleb=1;
fi;

orig_ndesc=$ndesc;
orig_maxsz=$maxsz;
orig_iter=$iter;
echo start `date` >> $sumf;

echo $fcnt

for (( b=$startb; $b < $maxb; b=( $b * $mulb ) )); do
	for (( fc=1; $fc <= $fcnt; fc=( $fc + 1 ) )); do
		sflg="echo \$flags$fc";
		sflg=`eval $sflg`;
		ststr="echo \$tstr$fc";
		ststr=`eval $ststr`;
		# Repeat for different cpl loop variants
		for (( cplfc=1; $cplfc <= $cplloopflags_cnt; cplfc=( $cplfc + 1 ), startcore=( ( $startcore + 1 ) % $maxcores ) )); do
			tmp="echo \$cplloopflags$cplfc";
			tmp=`eval $tmp`;
			flg="$sflg $tmp";
			tmp="echo \$cpllooptstr$cplfc";
			tmp=`eval $tmp`;
			tstr="$ststr $tmp";

			prevthresh=0;
			avg=0;
			core=$startcore;
			lcore=`expr $core + $numt - 1`;
			ndesc=$orig_ndesc;
			maxsz=$orig_maxsz;
			iter=$orig_iter;

			for (( x=$startsz; $x < $maxsz; x=( $x * 2 ) )); do
				it=$iter;
				stride=""
				if [ $mode = "lat" ]; then
					if [ $fc = 2 ]; then
						ndesc=2;
						init_devtlb_miss_stride
					else
						ndesc=1;
					fi
				fi
				if [ $mode = "bw" ]; then
					if (( $iter >= 10000 && $x > 64000 )); then
						it=`expr $iter / 10`;
					fi
				fi
				echo "==== op$op $tstr:batch$b $flg ${x}B ===" >> $outf;
				echo "==== op$op $tstr:batch$b $flg ${x}B ===";
				if [ $batch = "yes" ]; then
					nd=`expr $b \* $scaleb`;
					cmd="$bin -i${it} -n${nd} -b${b} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore -q$qd $stride";
				else
					cmd="$bin -i${it} -n${ndesc} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore -q$qd $stride";
				fi
				sum=0;
				val=0;
				cnt=0;
				start_it=$it;
				echo " " > $tmpf;
				for (( l=0; $l < $loop; l=( $l + 1 ) )); do
					echo " " > ${tmpf}1;
					if [ $flrCmd = "yes" ]; then
						echo "Issuing device reset" >> ${tmpf}1;
						for (( t=1; $t <= $numt; t=( $t + 1 ) )); do
							devn=`echo $dev |cut -d ':' -f$t`;
							echo 1 > /sys/bus/pci/devices/0000\:${devn}\:01.0/reset;
						done;
					fi
					echo "$cmd" >> ${tmpf}1;
					# run the test
					$cmd 1>>${tmpf}1 2>>${tmpf}1;
					# wait till this loop is done before dumping into the log
					cat ${tmpf}1 >> $tmpf;
					val=`egrep GB ${tmpf}1`;
					# if the test failed, it may not be found
					if (( $? == 0 )); then
						val=`egrep GB ${tmpf}1 |cut -d ' ' -f ${dfield} |cut -d '.' -f1`;
						if [ $mode = "bw" ]; then
							# try the next core if the data from this one is too low
							if (( $x > $startsz && ( $val == 0 || $val < $prevthresh ) )); then
								l=`expr $l - 1`;
								it=100;
								core=`expr $core + 1`;
								if (( $core >= $maxcores )); then
									core=0;
								fi
								lcore=`expr $core + $numt - 1`;
								if (( $core == $startcore )); then
									echo "Exhausted all cores.. giving up"
									l=$loop;
								else
									echo "Trying next core $core"
									if [ $batch = "yes" ]; then
										nd=`expr $b \* $scaleb`;
										cmd="$bin -i${it} -n${nd} -b${b} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore ";
									else
										cmd="$bin -i${it} -n${ndesc} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore ";
									fi
								fi
								sleep 1;
							else
								if (( $it != $start_it )); then
									# Issue appears to have cleared
									# Repeat for full iter
									it=$start_it;
									l=`expr $l - 1`;
									if [ $batch = "yes" ]; then
										nd=`expr $b \* $scaleb`;
										cmd="$bin -i${it} -n${nd} -b${b} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore ";
									else
										cmd="$bin -i${it} -n${ndesc} -s$x -w$wq_type -o$op $flg $misc_flg -k$core-$lcore ";
									fi
								#else
								#	#echo $val >> $sumf;
								#	sum=`expr $sum + $val`;
								#	cnt=`expr $cnt + 1`;
								fi
							fi
						#else
						#	#echo $val >> $sumf;
						#	sum=`expr $sum + $val`;
						#	cnt=`expr $cnt + 1`;
						fi
					fi
				done; # inner loop

				# append to the main log
				cat $tmpf >> $outf;
				cnt=`egrep GB $tmpf |wc -l`;
				# skip the top and bottom x% of values and average the rest
				cnts=`expr $cnt / $skip_pcnt`;
				cnte=`expr $cnt - $cnts`;
				vals=`egrep GB $tmpf |cut -d ' ' -f ${dfield} |cut -d '.' -f1 |sort -n`;
				l=0;
				cnt=0;
				for val in `echo $vals`; do
					if (( $l >= $cnts && $l < $cnte )); then
						sum=`expr $sum + $val`;
						cnt=`expr $cnt + 1`;
					fi;
					l=`expr $l + 1`;
				done;

				if (( $cnt != 0 )); then
					#threshold is 90% of previous data point
					avg=`expr $sum / $cnt`;
					prevthresh=`expr $avg / 10`;
					prevthresh=`expr $avg - $prevthresh`;
				else
					avg=0;
					prevthresh=0;
				fi
				echo "prevthresh: $prevthresh";
				echo "==== ${mode}_core$core op$op $tstr: $flg ${x}B : sum: $sum avg: $avg (cnt: $cnt) ===" >> $sumf;
				#echo "==== core$core op$op $tstr: $flg ${x}B : " `egrep GB $tmpf` >> $sumf;
				echo

				val1g=`expr 1024 \* 1024 \* 1024`;
				if (( ($b == 1) && ($x != $val1g) && (`expr $x \* 2` > $maxsz) )); then
					maxsz=$val1g;
					x=`expr $val1g / 2`;
					maxsz=`expr $maxsz + 1`;
					iter=10;
					ndesc=1;
				fi
			done; # data size variants
		done; #cpl loop variants
	done; #flag variants
done; # batch sizes
date

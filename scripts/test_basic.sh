#!/bin/bash

# Tests all opcodes on a single cpu

set -e

flags="-i1 -cf -zF,F"
bin="./src/dsa_perf_micros"
setup="./scripts/setup_dsa.sh"

test_all_ops() {
	bop=(0 3 16)
	eop=(0 9 21)
	n=${#bop[@]}

	for ((i=0; i<$n; i++)); do
		for ((o=${bop[$i]}; o<=${eop[$i]}; o++)); do
			echo "testing $o"
			$bin -o$o -n1 $*

			$bin -o$o -n2 -b2 $*
			$bin -o$o -n2 -b2 $* -a
		done
	done
}

test_params_loop() {
	d=dsa0
	$setup -d$d -w 1 -md

# test qd
	$bin -o3 -q16 -n32 -cf
# test offset
	$bin -o3 -O32,40 -cf
# test -T
	$bin -o3 -T2
}

test_all_cfg() {
	wq=(d s)
	d=dsa0

	for ((w=0; w<=1; w++)); do
		$setup -d$d -w 1 -m${wq[$w]}
		for pg in " " -l0 -l1; do
			test_all_ops $* $pg -w$w
		done
	done
}

test_cpu()
{
	for o in 3 4 6; do
		$bin -o$o -n1 -m $flags
	done
}

test_all_cfg $flags -k0
test_params_loop
test_cpu
echo "Unit test passed"

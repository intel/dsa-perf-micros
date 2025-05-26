#!/bin/bash

s_array=(512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k)
i_array=(10 100)
n_array=(128)
#s_array=(8k)
#i_array=(100)
#n_array=(1024)

nb_s=${#s_array[@]}
nb_i=${#i_array[@]}
nb_n=${#n_array[@]}

d_array=($(ls -v /sys/bus/dsa/devices/ | grep -e ^dsa))
nb_d=${#d_array[@]}

bin="./src/dsa_perf_micros"
flags="-cf -zF,F -x0x80"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# The runcmd() randomizes datasizes, arraysizes and descriptor counts from
# s_array, i_array and n_array respectively.
runcmd() {
    n=${n_array[(($RANDOM%$nb_n))]}
    s=${s_array[(($RANDOM%$nb_s))]}
    i=${i_array[(($RANDOM%$nb_i))]}
    cmd="$bin -n$n -s$s -i$i $flags $1"
    echo -e "${YELLOW}[......]${NC} $cmd\r\c"
    # $cmd >/dev/null 2>&1
    output=$($cmd 2>/dev/null)
    [ $? -eq 0 ] && echo -e "${GREEN}[Passed]${NC} $cmd" || echo -e "${RED}[Failed]${NC} $cmd"
    output2=$(echo "$output" | grep GB | cut -d " " -f 1-5)
    echo "$output2"
}

setup_dwq() {
    # FIXME: There is a driver bug in resetting IDBR register value on device reset.
    # the following rmmod and modprobe is to workaround this issue.
    rmmod idxd_vdev
    rmmod iaa_crypto
    rmmod idxd
    modprobe idxd

    ./scripts/setup_dsa.sh -d ${d_array[0]} -w8 -e1 -md
    [ $nb_d -ge 2 ] && ./scripts/setup_dsa.sh -d ${d_array[1]} -w8 -e1 -md
}

test_dwq() {
    echo "Testing DWQ"
    setup_dwq

    ## This section creates sample test commandlines to test
    #       different opcodes ( -o parameter )
    #       one or more submitters ( -K parameter )
    #       having one or both operands as interdomain. ( -r parameter )
    #       owner process information ( -R parameter )
    #           For one operand as interdomain (-r = 1/2)
    #               There should be same number of owners as submitters
    #           For both operands as interdomain (-r = 3)
    #               There should be twice the number of owners as submitters
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2 -R[5]@${d_array[0]},1"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x1 -R[5]@${d_array[0]},1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"

    ## This section creates sample test commandlines to test
    #       without -R parameter
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x3"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3"

    ## This section creates sample test commandlines to test SAMS functionality
    #       SAMS functionality is mentioned by second parameter of -r option.
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1 -R[5]@${d_array[0]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3,1"

    ## This section creates sample test commandlines to test multi device support
    #       Multiple dsa devices can be mentioned with -K parameter
    #       If -R parameter is used, then appropriate dsa device should be used in that also.

    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x1,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x2,0"

    runcmd "-K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x1,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x3,1"

    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,1"
    fi

    ## This section creates sample test commandlines to test update window descriptors
    #       The frequency of update window descriptors is given as 3rd argument of -r option
    runcmd "-K[1]@${d_array[0]},0                                        -o0x23 -r0x2,0,2 -R[5]@${d_array[0]},1"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x1,0,20 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x2,1,10"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    fi

    ## This section creates sample test commandlines to test window mode
    #       Window mode is specified by the 4th argument of -r option
    #       Default value for window mode is Address Mode (0)
    #       Specify 1 for window mode to enable Offset Mode.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1,0,1 -R[5]@${d_array[0]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    fi

    ## This section creates sample test commandlines to test window enable
    #       Window enable is specified by the 5th argument of -r option
    #       Default value for window enable is Enable (1)
    #       Specify 0 for window enable to disable inter domain window.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1,0,0,0 -R[5]@${d_array[0]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,0,0 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    fi

    ## This section creates sample test commandlines to test multiple IDPT windows
    #       Number of IDPT windows is specified by the 6th argument of -r option
    #       Default value for Window Count is 1
    #       For each owner, these many IDPT windows will be created
    #       The total IDPT Window count should not exceed the size of IDPT table for the platform.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,1,1,2"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,1,0,0,0,256 -R[5]@${d_array[0]},2"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,0,0,32"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,0,1,64 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,0,0,16 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,0,1,64"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,0,0,32 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2"
    fi
}

setup_swq() {
    # FIXME: There is a driver bug in resetting IDBR register value on device reset.
    # the following rmmod and modprobe is to workaround this issue.
    rmmod idxd_vdev
    rmmod iaa_crypto
    rmmod idxd
    modprobe idxd

    ./scripts/setup_dsa.sh -d ${d_array[0]} -w3 -e1 -ms
    [ $nb_d -ge 2 ] && ./scripts/setup_dsa.sh -d ${d_array[1]} -w3 -e1 -ms
}

test_swq() {
    echo "Testing SWQ"
    setup_swq

    ## This section creates sample test commandlines to test
    #       different opcodes ( -o parameter )
    #       one or more submitters ( -K parameter )
    #       having one or both operands as interdomain. ( -r parameter )
    #       owner process information ( -R parameter )
    #           For one operand as interdomain (-r = 1/2)
    #               There should be same number of owners as submitters
    #           For both operands as interdomain (-r = 3)
    #               There should be twice the number of owners as submitters
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x3 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x2 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x1 -R[5]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x3 -R[5-8]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x2 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x1 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x24 -r0x3 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x25 -r0x3 -R[5-8]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x26 -r0x3 -R[5-6]@${d_array[0]},0"

    ## This section creates sample test commandlines to test
    #       without -R parameter
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x3"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x2"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x3"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x2"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x24 -r0x3"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x25 -r0x3"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x26 -r0x3"

    ## This section creates sample test commandlines to test SAMS functionality
    #       SAMS functionality is mentioned by second parameter of -r option.
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x1,1 -R[5]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x2,1 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0   -o0x23 -r0x2,1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x3,1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x23 -r0x1,1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x24 -r0x3,1 -R[5]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x25 -r0x3,1 -R[5-6]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x26 -r0x3,1 -R[5]@${d_array[0]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x24 -r0x3,1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x25 -r0x3,1"
    runcmd "-K[1-2]@${d_array[0]},0 -o0x26 -r0x3,1"

    ## This section creates sample test commandlines to test multi device support
    #       Multiple dsa devices can be mentioned with -K parameter
    #       If -R parameter is used, then appropriate dsa device should be used in that also.
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,0 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,0 -R[5-8]@${d_array[0]},0 -R[9-12]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x1,0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x2,0"

    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x1,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x2,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,1"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,1"

    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,0 -R[5-8]@${d_array[0]},0 -R[9-12]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,1"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,1"
    fi

    ## This section creates sample test commandlines to test update window descriptors
    #       The frequency of update window descriptors is given as 3rd argument of -r option
    runcmd "-K[1]@${d_array[0]},0                  -o0x23 -r0x2,0,2 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0                  -o0x24 -r0x2,0,2"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,0,2 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,0,20 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,1,10"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1,5"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,0,10 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,0,3"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,1,15 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0"
    runcmd "-K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,1,100"
    fi

    ## This section creates sample test commandlines to test window mode
    #       Window mode is specified by the 4th argument of -r option
    #       Default value for window mode is Address Mode (0)
    #       Specify 1 for window mode to enable Offset Mode.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x24 -r0x3,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,1,0,1 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,10,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,3,1"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,1 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0"
    fi

    ## This section creates sample test commandlines to test window enable
    #       Window enable is specified by the 5th argument of -r option
    #       Default value for window enable is Enable (1)
    #       Specify 0 for window enable to disable inter domain window.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x24 -r0x3,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,1,0,0,0 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,10,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,3,0,0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,0,0 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0"
    fi

    ## This section creates sample test commandlines to test multiple IDPT windows
    #       Number of IDPT windows is specified by the 6th argument of -r option
    #       Default value for Window Count is 1
    #       For each owner, these many IDPT windows will be created
    #       The total IDPT Window count should not exceed the size of IDPT table for the platform.
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,1,1,2"
    runcmd "-K[1]@${d_array[0]},0              -o0x23 -r0x2,1,0,0,0,256 -R[5]@${d_array[0]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,0,0,32"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,0,1,64 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0"
    if [ $nb_d -ge 2 ]
    then
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,0,0,16 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,0,1,64"
    runcmd "-K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,0,0,32 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0"
    fi
}

test_dwq
test_swq

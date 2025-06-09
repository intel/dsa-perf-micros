


echo Testing SWQ Interdomain

#rmmod idxd_vdev iaa_crypto idxd
#cd /lib/modules/$(uname -r)/source/drivers/dma/idxd
#./install-custom-idxd.sh
#cd -

d_array=($(ls -v /sys/bus/dsa/devices/ | grep dsa))
../scripts/setup_dsa.sh -d ${d_array[0]} -w8 -e1 -ms
../scripts/setup_dsa.sh -d ${d_array[1]} -w8 -e1 -ms


../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x3 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x2 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x3 -R[5-8]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x2 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x1 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x24 -r0x3 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x25 -r0x3 -R[5-8]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x26 -r0x3 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x24 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x25 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x26 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x1,1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x2,1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x23 -r0x2,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x23 -r0x1,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x24 -r0x3,1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x25 -r0x3,1 -R[5-6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x26 -r0x3,1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x24 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x25 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x26 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,0 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,0 -R[5-8]@${d_array[0]},0 -R[9-12]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x1,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x2,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x1,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x2,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,0 -R[5-8]@${d_array[0]},0 -R[9-12]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,0 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,1 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,1 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                  -o0x23 -r0x2,0,2 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                  -o0x24 -r0x2,0,2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x3,0,2 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x1,0,20 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x23 -r0x2,1,10 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x23 -r0x3,1,5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,0,10 -R[5-6]@${d_array[0]},0 -R[7-8]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x25 -r0x3,0,3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x26 -r0x3,1,15 -R[5]@${d_array[0]},0 -R[7]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x24 -r0x3,1,100 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x24 -r0x3,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,1,0,1 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,10,1 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,1 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x24 -r0x3,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x2,1,0,0,0 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,10,0,0 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,3,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,0,0 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x3,0,0,1,1,2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,1,0,0,0,256 -R[5]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x23 -r0x1,1,0,0,0,32 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x25 -r0x3,1,0,0,1,64 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x25 -r0x3,0,0,0,0,16 -R[5]@${d_array[0]},0 -R[6]@${d_array[0]},0 -R[7]@${d_array[0]},0 -R[8]@${d_array[0]},0 -R[9]@${d_array[1]},0 -R[10]@${d_array[1]},0 -R[11]@${d_array[1]},0 -R[12]@${d_array[1]},0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x24 -r0x3,0,0,0,1,64 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x26 -r0x3,1,15,0,0,32 -R[5]@${d_array[0]},0 -R[9]@${d_array[1]},0 2>/dev/null | grep GB



echo Testing SWQ non-Interdomain
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                  -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                  -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0   -K[3]@${d_array[1]},0   -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1-2]@${d_array[0]},0 -K[3-4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},0 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},0 -o0x6 2>/dev/null | grep GB



echo Testing DWQ Interdomain

#rmmod idxd_vdev iaa_crypto idxd
#cd /lib/modules/$(uname -r)/source/drivers/dma/idxd
#./install-custom-idxd.sh
#cd -

../scripts/setup_dsa.sh -d ${d_array[0]} -w8 -e1 -md
../scripts/setup_dsa.sh -d ${d_array[1]} -w8 -e1 -md


../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2 -R[5]@${d_array[0]},1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x1 -R[5]@${d_array[0]},1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1 -R[5]@${d_array[0]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x26 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x1,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x2,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x3,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x1,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                                        -o0x23 -r0x2,0,2 -R[5]@${d_array[0]},1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x23 -r0x1,0,20 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x23 -r0x2,1,10 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1,0,1 -R[5]@${d_array[0]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10,1 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3,1 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,1 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x24 -r0x3,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x2,1,0,0,0 -R[5]@${d_array[0]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,10,0,0 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,3,0,0 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,0,0 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x3,0,0,1,1,2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x23 -r0x2,1,0,0,0,256 -R[5]@${d_array[0]},2 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x23 -r0x1,1,0,0,0,32 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x25 -r0x3,1,0,0,1,64 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x25 -r0x3,0,0,0,0,16 -R[5]@${d_array[0]},2 -R[6]@${d_array[0]},3 -R[7]@${d_array[0]},4 -R[8]@${d_array[0]},5 -R[9]@${d_array[1]},2 -R[10]@${d_array[1]},3 -R[11]@${d_array[1]},4 -R[12]@${d_array[1]},5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x24 -r0x3,0,0,0,1,64 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x26 -r0x3,1,15,0,0,32 -R[5]@${d_array[0]},2 -R[9]@${d_array[1]},2 2>/dev/null | grep GB


echo Testing DWQ non-Interdomain
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0                                        -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[3]@${d_array[1]},0                           -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x6 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0              -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x3 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x5 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x4 2>/dev/null | grep GB
../src/dsa_perf_micros -n1024 -s32k -i100 -cf -zF,F -x0x80 -K[1]@${d_array[0]},0 -K[2]@${d_array[0]},1 -K[3]@${d_array[1]},0 -K[4]@${d_array[1]},1 -o0x6 2>/dev/null | grep GB

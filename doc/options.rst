.. ***************************************************************************
 .. * Copyright 2022 Intel Corporation.
 .. *
 .. * This software and the related documents are Intel copyrighted materials,
 .. * and your use of them is governed by the express license under which they
 .. * were provided to you ("License"). Unless the License provides otherwise,
 .. * you may not use, modify, copy, publish, distribute, disclose or transmit
 .. * this software or the related documents without Intel's prior written
 .. * permission.
 .. *
 .. * This software and the related documents are provided as is, with no
 .. * express or implied warranties, other than those that are expressly
 .. * stated in the License.
 .. *
 .. ***************************************************************************/

Command Line Options
====================

.. option:: -b <batch size>

   Use batch descriptors with "batch size" descriptors in a batch.

.. option:: -B PCI device/resource+offset_into_mmio to map memory from

   (e.g., m,Bus:Device.Function/resource0+4096 => memory is src, B:D.F/resource0+4096 is dst)

.. option:: -c

   Increment portal address between descriptors.

.. option:: -D <delta percentage>

   Delta (specified as a percentage) between buffers for delta create and delta apply

.. option:: -e <block length>

   Block length [0-3] for dif operations

.. option:: -f

   Set the cache control flag in descriptors.

.. option:: -F <flag_bits_to_clear:flag_bits_to_set:every_nth_desc>

   (e.g. -F 0xFFFFF7:0x8:4 to clear Addr2_TC flag and set RCR=1 on every 4th descriptor)

.. option:: -h

   Show help.

.. option:: -i <iteration count>

   The number of iterations to run the test for

.. option:: -j

   Continuously stream descriptors to the device (use for bandwidth measurment)

.. option:: -k <CPU list>

   List of CPUs (e.g., -k0, -k0,1,2,3, -k0-2, -k0-2,3)

.. option:: -K <CPU/WQ list>

   List of CPUs and associated WQ (e.g., [0,1]@dsa0,0,[2-3]@dsa0,1)

.. option:: -l <0/1>

   Use large pages, 0 for 2M, 1 for 1G.

.. option:: -m

   Use CPU to implement opcodes.

.. option:: -n <buffer count>

   Buffer count

.. option:: -o <opcode>

   DSA opcode

.. option:: -P

   Use processes instead of threads.

.. option:: -q <queue depth>

   Queue depth for dedicated WQ, can be > WQ size (use with -j)

.. option:: -s <size>

   Transfer size in bytes, can use k,m,g to specify KiB/MiB/GiB (e.g., -b 200m)

.. option:: -S <Numa Node ID list>

   Numa node ID list for b1, b2, b3 allocation, -1 is used for memory allocation
   from CPUs NUMA node (e.g., -k0,59 -S-1,1 -S-1,0 allocates memmove source from
   node 0 and destination from node 1 for CPU0, and allocates memmove source from
   node 1 and destination from node 1 for CPU59 if CPU59 were on NUMA node 1)

.. option:: -t <stride>

   Stride between buffer start addresses

.. option:: -T <time in seconds>

   Time interval for BW measurement (use with -i-1)

.. option:: -u<engine count>

   Use user mode driver (VFIO/UIO)

   Optional parameter specifies device engine count (defaults to max engines in device)

.. option:: -w <0/1>

   WQ type, 0 => dedicated WQ, 1 => shared WQ

.. option:: -W <warmup interations>

   Device TLB/IOMMU TLB/cache warmup loop count (not included in measurements,
   Use for latency measurements

.. option:: -x <Hexadecimal mask>

   bit0      => init device TLB each iteration (use for latency measurments)

   bits[1:5] => movdir64/enqcmd submission rate test

   bit[7:8]  => pause(7)/umwait(8) in completion wait (use for latency measurement)

   Rest      => unused

.. option:: -v <0/1>

   Verify result (0 => disable, 1 => enable, default is enable)

.. option:: -y <CPU access specifier list>

   Comma seperated list used to specify how DSA operands (None/Read/Write) are
   accessed by the CPU before descriptors are issued.

.. option:: -Y

   Convert last descriptor to drain descriptor.

.. option:: -z <Data Placement Specifier List>

   Comma separated list of directives for data placement for respective buffers.
   the specifiers are -P (fetch into the L1 cache), -D (demote to LLC),
   -F (flush to memory)

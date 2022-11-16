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

Sample Command Lines
====================

* Dedicated WQ configuration

  Dedicated WQ of max size (128) with 4 engines

.. code-block:: console

 $ ./scripts/setup_dsa.sh -d dsa0 -w 1 -m d -e 4

* Shared WQ configuration

  Shared WQ of max size (128) with 4 engines

.. code-block:: console

 $ ./scripts/setup_dsa.sh -d dsa0 -w 1 -m s -e 4

* Dedicated WQ Bandwidth

  Stream memmove descriptors from single cpu core (core 5) to DWQ on DSA device.
  Submit upto queue depth of 128, each descriptor with transfer size = 4KB,
  source data in memory, destination write allocated in the LLC (i.e. set cache control flag to 1).
  Run 1000 iterations with continuous descriptor submission (i.e. submit new descriptors
  each time one or more complete). Each descriptor submission uses a different
  cacheline address in the work queue portal region. For DWQs there can be multiple
  movdir64b instructions in flight and with "-c", we get higher throughput of
  movdir64b instructions through the SoC fabric.

.. code-block:: console

 $ ./src/dsa_perf_micros -n128 -s4k -j -c -f -i1000 -k5 -w0 -zF,F -o3

* Shared WQ Bandwidth

  To keep the DSA fully busy we use 4 CPUs to account for the higher latency of
  the enqcmd instruction. The "-c" parameter is not relevant here since there can be only
  a single enqcmd instruction in flight at any given point.

.. code-block:: console

 $ ./src/dsa_perf_micros -n128 -s4k -j -f -i1000 -k5-8 -w1 -zF,F -o3

* Batch Descriptor Memove Bandwidth

  Batch descriptors can be used to keep the device fully busy and obtain maximum
  memove bandwidth  when submitting from a single CPU to a shared WQ.

.. code-block:: console

  $ ./src/dsa_perf_micros -n$(( 128 * 4 )) -b4  -s4k -j -f -i1000 -k5 -w1 -zF,F -o3

* Latency Measurement

  Measure latency of single memmove descriptor with synchronous completion;
  submitted from single cpu core (core 1) to DWQ on DSA device. Each memmove is
  1KB size, source data in memory, destination write allocated in the LLC
  (i.e., set cache control flag to 1). Use a group that has a single engine for
  these measurements to avoid overlap of consecutive operations.

  * Measure with IOMMU Non-Leaf Cache hit, device TLB miss. Use a stride that is the max
    of (page size, align_high(transfer size, page size)). This test uses 2 pairs of src
    and dest buffers, since the test uses a single engine and the stride between
    src addresses (and dest addresses) in the 2 descriptors is 4K, the
    src and dest addresses of any given descriptor miss the TLB entry installed as part
    of executing the previous descriptor.

  .. code-block:: console

     $ ./src/dsa_perf_micros -n2 -w0 -o3 -zF,F -f -s1k -i100 -k1 -q1 -t4k

  * Measure with device TLB hit.

  .. code-block:: console

     $ ./src/dsa_perf_micros -n1 -w0 -o3 -zF,F -f -s1k -i100 -k1 -q1

* Multiple DSAs with Dedicated WQ (use different cores if SNC mode is turned on).
  Any Dedicated DSA WQ within the same NUMA node is selected if available.

.. code-block:: console

   $ ./src/dsa_perf_micros -jcf -k0-3 -n32 -o3 -zF,F

* Multiple DSAs with Shared WQ (use different cores if SNC mode is turned on).

.. code-block:: console

   $ ./src/dsa_perf_micros -jcf -K[0-3]@dsa0,0 -K[4-7]@dsa2,0 -K[8-11]@dsa4,0 -K[12-15]@dsa6,0 -n32 -o3 -zF,F

* Running with logging enabled (Build with logging enabled as described in build
  steps)

.. code-block:: console

   $ DSA_PERF_MICROS_LOG_LEVEL=info ./src/dsa_perf_micros -jcf -k0-3  -n32 -o3 -zF,F -i10000

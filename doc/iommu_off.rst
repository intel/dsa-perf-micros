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

intel_iommu=off mode/VT-D disabled
==================================

DSA Micros uses DPDK's NUMA aware memory management when using physical addresses if either intel_iommu=off is
specified on the kernel command line mode or VT-D is disabled in the BIOS.

Install dpdk libraries for your OS.

.. code-block:: console

   $ dnf install dpdk

OR

.. code-block:: console

   $ apt install dpdk

DSA Micros tries to locate for the DPDK EAL library (librte_eal.so) in a couple of standard directories,
in case it errors out, supply the complete file path on your system in the DSA_PERF_MICROS_EAL_PATH env.
variable.

.. code-block:: console

   $ export DSA_PERF_MICROS_EAL_PATH=/usr/lib64/librte_eal.so.21

Bind device to uio_pci_generic

.. code-block:: console

   $ ./scripts./pci_bind.sh uio_pci_generic b:d.f

Provide the -u command line argument

.. code-block:: console

   $ ./src/dsa_perf_micros -u -n128 -s4k -j -c -f -i1000

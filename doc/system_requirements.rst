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

System Requirements
*******************

- CPU with Intel® Data Streaming Accelerator (Sapphire Rapids and higher)
- Kernel version 5.10 or higher (https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-driver-dma-idxd)
- For kernels without enqcmd support (5.13 >= version <= 5.17), the link to the patch that re-enables enqcmd support is below.
  https://lore.kernel.org/lkml/20210920192349.2602141-1-fenghua.yu@intel.com/T/#rd6d542091da1d1159eda0a44a16e57d0c0dfb209
- dsa_perf_micros uses the x86_energy_perf_policy and cpupower applications to tune CPU power management for performance, these applications can be built/installed from the kernel source tree or installed using the OS package management utilities. If these applications are missing, dsa_perf_micros will print corresponding error messages but continue to work.

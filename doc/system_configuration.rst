
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

System Configuration
********************
* Enable VT-D/IOMMU in the BIOS
* Enable VT-D scalable mode in the kernel

.. code-block:: console

   CONFIG_INTEL_IOMMU_SVM=y

* Enable the IDXD driver in the kernel

.. code-block:: console

   CONFIG_INTEL_IDXD=m
   CONFIG_INTEL_IDXD_SVM=y

* Enable VT-D and VT-D scalable mode in the kernel boot parameters

.. code-block:: console

   intel_iommu=on,sm_on

OR

* Enable VT-D and VT-D scalable mode by default in the kernel

.. code-block:: console

   CONFIG_INTEL_IOMMU_DEFAULT_ON=y
   CONFIG_INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON

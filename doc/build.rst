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

Build
#####

Prerequisites
*************

* Libraries:

  * accel-config (https://github.com/intel/idxd-config) version 3.4.5 or higher
  * libnuma


Build Steps
***********
1. Extract git sources using the following command:

.. code-block:: console

 $ git clone https://github.com/intel/dsa_perf_micros/

2. Use the steps below to build the dsa_perf_micros application

.. code-block:: console

 $ ./autogen.sh
 $ ./configure CFLAGS='-g -O2' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib
 $ make

The resulting application is available in src/dsa_perf_micros.

 To enable logging, use the configure command line below.

.. code-block:: console

 $ ./configure CFLAGS='-g -O2 -DENABLE_LOGGING' --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib

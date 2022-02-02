DSA Configuration
=================

The DSA can be configured using accel-config, check https://01.org/blogs/2020/pedal-metal-accelerator-configuration-and-control-open-source to learn more. We have provided a few sample configuration files in the configs directory, these can be used as below

.. code-block:: console

 $ ./scripts/setup_dsa.sh configs/4e1w-d.conf

The setup_dsa.sh script can also be used to use setup a dedicated DSA WQ with 4 engines using the command below.

.. code-block:: console

 $ ./scripts/setup_dsa.sh -d dsa0 -w 1 -m d -e 4

To learn more about the setup_dsa.sh script use the command below.

.. code-block:: shell

 $./scripts/setup_dsa.sh

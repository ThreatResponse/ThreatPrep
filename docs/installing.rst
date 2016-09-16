
============
Installation
============

Install From PyPi
*****************

.. code-block:: bash

   $ pip install awsthreatprep

Install From Github
*******************

.. code-block:: bash

   $ pip install git+git://github.com/ThreatResponse/ThreatPrep@master


Docker Example
**************

Below we show a working installation procedure in a minimized `python docker container <https://hub.docker.com/_/python/>`__.

.. code-block:: bash

   $ docker run -it -e AWS_ACCESS_KEY_ID=AWSACCESSKEYHERE -e AWS_SECRET_ACCESS_KEY=AWSSECRETACCESSKEYHERE python:2 bash
   root@3009:/# pip install awsthreatprep


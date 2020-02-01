Installation
============

Mumpy has not been released on PyPI yet, so it must be cloned from the Git repo and installed manually.

.. code:: bash

    $ pip3 install --user git+https://github.com/ianling/mumpy.git

Requirements
------------

* Python 3.6+
    * opuslib
    * pycryptodome
    * protobuf
* libopus (for audio)
    * Debian/Ubuntu: `apt install libopus0`
    * OSX: `brew install opus`
    * Windows: http://opus-codec.org/downloads/
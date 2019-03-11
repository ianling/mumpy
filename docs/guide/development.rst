Development
===========

Mumpy is open source under the GNU General Public License (GPL) version 3. The source code can be found `on Github`_.

.. _on Github: https://github.com/ianling/mumpy/

Contributing
------------

If you have any contributions to make, whether they are bug reports, feature requests, or even code, feel free to submit
issues and pull requests `on Github`_.

This repo uses Travis CI to run a Python style checker called flake8, which looks for errors in the code, as well
as deviations from the PEP8 style guide.

In order to style check your code locally before pushing it to Github, you can run a command like the following, from
the root of the repo:

.. code:: bash

    $ python3 -m flake8 .

We also ignore some of the flake8 style suggestions. Check the `Travis config file`_ in the repo to see exactly what
flake8 command will get run on code pushed to the repo.

.. _Travis config file: https://github.com/ianling/mumpy/blob/master/.travis.yml

Building the Documentation
--------------------------

To build the documentation locally, enter the ``docs/`` directory and run the command ``make html``.
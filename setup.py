from setuptools import setup, find_packages

setup(name='Mumpy',
      version='1.0b',
      description='Mumble Client Framework',
      author='Ian Ling',
      include_package_data=True,
      packages=find_packages(),
      install_requires=['opuslib', 'pycryptodome', 'protobuf']
      )
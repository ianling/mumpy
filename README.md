# Mumpy [![Docs](https://readthedocs.org/projects/mumpy/badge/?version=latest)](https://mumpy.readthedocs.io/) [![CI](https://api.travis-ci.com/ianling/mumpy.svg?branch=master)](https://travis-ci.com/ianling/mumpy/branches#)

Mumpy is a Mumble client and server framework written in Python 3. It aims to be a client fully compatible with the official Mumble server (Murmur), as well as a server fully compatible with the official Mumble client.

Mumpy is event-driven, making it perfect for writing Mumble bots.

This project is still in development and has not yet been officially released. That said, it is usable, but I can't guarantee that function names will remain the same. If you have a feature request, please feel free to create an issue.

## Requirements

* Python 3.6+
    * opuslib
    * pycryptodome
    * protobuf
* libopus (for audio)
    * Debian/Ubuntu: `apt install libopus0`
    * OSX: `brew install opus`
    * Windows: http://opus-codec.org/downloads/

## Documentation

Examples, API docs, and other documentation are all available over on [ReadTheDocs](https://mumpy.readthedocs.io/).

## General To-do

* Allow specifying callback functions on certain actions, instead of having to listen for related events

## Client To-do

* Fix audio crackling issue
* Add remaining client protobuf message types (including ContextActionModify and ContextAction)
* Allow sending other audio besides 48KHz 16-bit WAV/PCM
* Add per-user audio storage limits
* Mixdown audio
* Send server the client's connection stats
* Support SRV records when connecting to a server
* A better way to store audio than a list of potentially massive byte strings on each user
* Add function to manually kill UDP connection and switch back to TCP
* Handle position data in audio transmissions

## Server To-do

* Fully compatible with official Mumble clients


## Thanks

Big thanks to [@Lartza](https://github.com/Lartza) and [@Azlux](https://github.com/azlux) for their work on pymumble, as well as everyone's insight in #mumble on Freenode.net.

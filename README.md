# Mumpy [![Docs](https://readthedocs.org/projects/mumpy/badge/?version=latest)](https://mumpy.readthedocs.io/)

Mumpy is a Mumble client framework written in Python 3.

It is event-driven, making it perfect for writing Mumble bots.

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

## To-do (in order of priority)

* Add remaining client protobuf message types (including ContextActionModify and ContextAction)
* Allow sending other audio besides 48KHz 16-bit WAV/PCM
* Add per-user audio storage limits
* Mixdown audio
* A better way to store audio than a list of potentially massive byte strings on each user
* Add function to manually kill UDP connection and switch back to TCP

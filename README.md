# Mumpy

Mumpy is a Mumble client framework written in Python3.

Mumpy is a work in progress. It will be fully compliant to the Mumble protocol, and implement all of the different low-level protocol messages that are needed for a client to function.

It is event-driven, making it perfect for writing Mumble bots.

## Requirements

* Python 3.6+
    * opuslib (https://github.com/OnBeep/opuslib)
    * pycryptodome
    * protobuf
* libopus (for audio)

## Example

Below is some basic code to get you started. It creates a bot and adds a function to handle CONNECTED events. This event handler function sends a text message to everyone in the bot's current channel, then disconnects from the server after 5 seconds. Once all the bot has disconnected, execution ends.

    from mumpy import Mumpy, MumpyEvent
    from time import sleep
    
    def connected_event_handler(bot, raw_message):
        bot.text_message("Hello everyone, I just connected. My name is {0}.".format(bot.username))
        sleep(5)
        bot.text_message("I am leaving now, goodbye.")
        bot.disconnect()
    
    my_bot = Mumpy(username="MyBot")
    my_bot.add_event_handler(MumpyEvent.CONNECTED, connected_event_handler)
    my_bot.connect('localhost')  # port=64738 by default
    
    while my_bot.is_alive():
        print("The bot is still alive.")
        sleep(3)
    
    logging.info("All bots have died!")

## Events

There are a number of different event types you can write handlers for.

* MumpyEvent.CONNECTED
    * Fired when the client has connected and authenticated successfully.
* MumpyEvent.DISCONNECTED
    * Fired when the client has disconnected from the server. May be preceded by a USER_KICKED and a USER_BANNED event.
* MumpyEvent.UDP_CONNECTED
    * Fired when the client has successfully established a UDP connection to the server
* MumpyEvent.UDP_DISCONNECTED
    * Fired when the client has lost or intentionally ended the UDP connection. This implies that audio communications have changed back to using the TCP connection.
* MumpyEvent.CHANNEL_ADDED
    * Fired when a channel is added to the server.
* MumpyEvent.CHANNEL_UPDATED
    * Fired when a channel is updated or modified in some way.
* MumpyEvent.CHANNEL_REMOVED
    * Fired when a channel is removed from the server.
* MumpyEvent.USER_CONNECTED
    * Fired when someone else connects to the server.
* MumpyEvent.USER_DISCONNECTED
    * Fired when someone else disconnects from the server. May be preceded by a USER_KICKED and a USER_BANNED event.
* MumpyEvent.USER_KICKED
    * Fired when anyone is kicked from the server.
* MumpyEvent.USER_BANNED
    * Fired when anyone is banned from the server.
* MumpyEvent.USER_STATS_UPDATED
    * Fired when updated stats about a user are received. This happens after the client specifically requests stats about a user.
* MumpyEvent.USER_REGISTERED
    * Fired when a user registers on the server.
* MumpyEvent.USER_COMMENT_UPDATED
    * Fired when a user changes their comment.
* MumpyEvent.USER_AVATAR_UPDATED
    * Fired when a user changes their avatar.
* MumpyEvent.USER_SELF_MUTED / USER_SELF_UNMUTED
    * Fired when a user mutes or unmutes themselves.
* MumpyEvent.USER_SELF_DEAFENED / USER_SELF_UNDEAFENED
    * Fired when a user deafens or undeafens themselves.
* MumpyEvent.USER_MUTED / USER_UNMUTED
    * Fired when a user is muted / unmuted server side (e.g. by a server admin).
* MumpyEvent.USER_DEAFENED / USER_UNDEAFENED
    * Fired when a user is deafened / undeafened server side (e.g. by a server admin).
* MumpyEvent.USER_RECORDING / USER_STOPPED_RECORDING
    * Fired when a user starts / stops recording.
* MumpyEvent.MESSAGE_RECEIVED
    * Fired when a text message is received.
* MumpyEvent.MESSAGE_SENT
    * Fired when the client sends a text message.
* MumpyEvent.AUDIO_TRANSMISSION_RECEIVED
    * Fired when the client has received a complete audio transmission from the server.
* MumpyEvent.AUDIO_TRANSMISSION_SENT
    * Fired when the client has sent a complete audio transmission to the server.
* MumpyEvent.AUDIO_DISABLED
    * Fired when the client disables audio processing. This happens when the client fails to initialize the chosen audio codec, or does not support any of the server's audio codecs.
* MumpyEvent.AUDIO_ENABLED
    * Fired when the client enables audio processing. This happens when the client initially connects to the server and successfully initializes an audio codec.
* MumpyEvent.BANLIST_MODIFIED
    * Fired when the server's ban list is modified.

## Client Methods

The Mumpy object exposes many different methods and attributes you can use to interact with the server and other clients.

* [void] connect(address, port=64738, certfile=None, keyfile=None, keypassword=None)
    * Connects to _address_:_port_. Specify certfile, keyfile, and (optionally) keypassword to load an SSL certificate. 
    * To generate a self-signed SSL certificate and key, you can run a command like: 
      `openssl req -newkey rsa:2048 -nodes -keyout mumpy_key.pem -x509 -days 2000 -out mumpy_certificate.pem`
* [void] disconnect()
    * Disconnects from the server.
* [bool] is_alive()
    * Returns True if the client is connected to a server.
* [dict] get_users()
    * Returns a dictionary of all the Users in the server, in the form: users[session_id] = User()
    * Example: bot.get_users()[session_id].name
* [dict] get_channels()
    * All the channels in the server.
    * Example: bot.get_channels()[id].name
* [string] get_current_username()
    * Returns the client's current username.
* [int] get_current_user_id()
    * Returns the client's current user session ID.
* [string] get_current_channel()
    * Returns the client's current Channel.
* [int] get_current_channel_id()
    * Returns the id of the client's current channel.
* [string] get_user_by_id(id)
    * Returns the User object identified by the session ID _id_.
* [int] get_user_by_name(username)
    * Returns the User object identified by _username_.
* [string] get_channel_by_id(id)
    * Returns the Channel identified by _id_.
* [int] get_channel_by_name(channel_name)
    * Returns the Channel identified by _channel_name_.
* [void] kick_user(User, reason="", ban=False)
    * Kicks the User from the server. Bans the user if ban is True.
* [void] kick_user_by_name(username, reason="", ban=False)
    * Kicks the User identified by _username_. Bans the user if ban is True.
* [void] text_message(message, channels=[], users=[])
    * Sends _message_ to each Channel in _channels_, and each User in _users_. If no Channels or Users are provided, sends the message to the client's current channel.
* [list] get_user_audio_log(User)
    * Retrieves a list of all completed audio transmissions received from the User. Each element in the list is a byte string containing the raw PCM audio data from that transmission.

## To-do (in order of priority)

* Comment text and comment picture request method (RequestBlob)
* Add remaining client protobuf message types (including ContextActionModify and ContextAction)
* Allow sending other audio besides 48KHz 16-bit WAV/PCM
* Add per-user audio storage limits
* Mixdown audio
* A better way to store audio than a list of potentially massive byte strings on each user
* Add function to manually kill UDP connection and switch back to TCP

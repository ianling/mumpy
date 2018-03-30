# Mumpy

Mumpy is a Mumble client framework written in Python3.

Mumpy is a work in progress. It will be fully compliant to the Mumble protocol, and implement all of the different low-level protocol messages that are needed for a client to function.

It is event-driven, making it perfect for writing Mumble bots.

## Example

Below is some basic code to get you started. It creates two bots, and adds a function to handle CONNECTED events to each. This function sends a message to the bot's current channel, then disconnects from the server after 5 seconds. Once all the bots have disconnected, execution ends.

    import logging
    from mumpy import Mumpy, MumpyEvent
    from time import sleep

    def connected_event_handler(bot, raw_message):
        bot.text_message("Hello everyone, my name is {0}.".format(bot.username))
        sleep(5)
        bot.text_message("I am leaving now, goodbye.")
        bot.disconnect()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    bot_a = Mumpy(username="MyBot")
    bot_a.add_event_handler(MumpyEvent.CONNECTED, connected_event_handler)
    bot_a.connect('localhost')  # port=64738 by default
    sleep(1)
    bot_b = Mumpy(username="SomeOtherBot")
    bot_b.add_event_handler(MumpyEvent.CONNECTED, connected_event_handler)
    bot_b.connect('localhost')

    bots = []
    bots.append(bot_a)
    bots.append(bot_b)

    while any(bot.is_alive() for bot in bots):
        logging.info("There is still at least one bot alive.")
        sleep(3)

    logging.info("All bots have died!")

## Events

There are a number of different event types you can write handlers for.

* MumpyEvent.CONNECTED
    * Fired when the client has connected and authenticated successfully.
* MumpyEvent.DISCONNECTED
    * Fired when the client has disconnected from the server. May be preceded by a USER_KICKED and a USER_BANNED event.
* MumpyEvent.CHANNEL_ADDED
    * Fired when a channel is added to the server.
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
* MumpyEvent.MESSAGE_RECEIVED
    * Fired when a text message is received.
* MumpyEvent.MESSAGE_SENT
    * Fired when the client sends a text message.
* MumpyEvent.BANLIST_MODIFIED
    * Fired when the server's ban list is modified.

## Client Methods

The Mumpy object exposes many different methods and attributes you can use to interact with the server and other clients.

* [void] connect(address, port=64738)
    * Connects to _address_:_port_.
* [void] disconnect()
    * Disconnects from the server.
* [bool] is_alive()
    * Returns True if the client is connected to a server.
* [dict] get_users()
    * All the users in the server.
    * Example: bot.get_users()[id]["name"]
* [dict] get_channels()
    * All the channels in the server.
    * Example: bot.get_channels()[id]["name"]
* [string] get_current_username()
    * Returns the client's current username.
* [int] get_current_user_id()
    * Returns the client's current user session ID.
* [string] get_current_channel_name()
    * Returns the name of the client's current channel.
* [int] get_current_channel_id()
    * Returns the id of the client's current channel.
* [string] get_user_name_by_id(id)
    * Returns the name of the user identified by _id_.
* [int] get_user_id_by_name(username)
    * Returns the session ID of the user identified by _username_.
* [string] get_channel_name_by_id(id)
    * Returns the name of the channel identified by _id_.
* [int] get_channel_id_by_name(channel_name)
    * Returns the channel ID of the channel identified by _channel_name_.
* [void] kick_user_by_id(id, reason="", ban=False)
    * Kicks the user identified by _id_. Bans the user if ban is True.
* [void] kick_user_by_name(username, reason="", ban=False)
    * Kicks the user identified by _username_. Bans the user if ban is True.
* [void] text_message(message, channels=[], users=[])
    * Sends _message_ to each channel in _channels_, and each user in _users_. If no channels or users are provided, sends the message to the client's current channel.

## To-do

* Everything related to voice data, including UDP and TCP tunneling.
* Handle remaining message types, add more event types

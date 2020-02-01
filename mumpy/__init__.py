from mumpy.client import Client
from mumpy.constants import EventType
from mumpy.server import Server

__all__ = ['Client', 'EventType', 'Server']


def main():
    import logging
    import sys
    from time import sleep
    from argparse import ArgumentParser

    argument_parser = ArgumentParser()
    argument_parser.add_argument('-c', '--certfile', required=True)
    argument_parser.add_argument('-k', '--keyfile', required=True)
    argument_parser.add_argument('-H', '--host', default='0.0.0.0')
    argument_parser.add_argument('-p', '--port', type=int, default=64738)
    argument_parser.add_argument('-v', '--verbose', action="store_true", default=False)
    args = argument_parser.parse_args()

    root = logging.getLogger()
    if args.verbose:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    root.setLevel(logging_level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    server = Server(certfile=args.certfile, keyfile=args.keyfile, host=args.host, port=args.port)
    while server.is_alive():
        sleep(5)


if __name__ == '__main__':
    main()

import json
import logging
import sys

import click


@click.command(short_help="unpack replay")
def unpack():
    pass


@click.command(short_help="disassemble into packets")
def dis():
    pass


@click.command(short_help="assemble packets")
def asm():
    pass


@click.command(short_help="pack replay")
def pack():
    pass


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def main(verbose):
    """
    World of Tanks Replay Toolkit.

    Use `unpack` command followed by `dis` command to unpack replay into sequence of packets.

    Use `asm` command followed by `pack` command to pack sequence of packets back into replay.
    """
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        level=(logging.INFO if not verbose else logging.DEBUG),
        stream=sys.stderr,
    )


main.add_command(unpack)
main.add_command(dis)
main.add_command(asm)
main.add_command(pack)


if __name__ == '__main__':
    main()

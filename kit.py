import json
import logging
import struct
import sys
import zlib

import click


@click.command(short_help="Unpack replay.")
@click.argument("replay", type=click.File("rb"))
@click.option("-1", "--first", help="First JSON part output.", required=True, type=click.File("wt"))
@click.option("-2", "--second", help="Second JSON part output.", required=True, type=click.File("wt"))
@click.option("-p", "--packets", help="Packets output.", required=True, type=click.File("wt"))
def unpack(replay, first, second, packets):
    """
    Unpacks replay file into JSON parts and raw packets part.

    Example use:

    \b
    kit.py unpack
        20140810_1853_usa-M18_Hellcat_28_desert.wotreplay
        -1 first.json
        -2 second.json
        -p packets.bin
    """
    pass


@click.command(short_help="Disassemble into packets.")
def dis():
    """
    Disassembles binary packets part into plain text packets description.

    Example use:

    \b
    kit.py dis
        packets.bin
        -o packets.txt
    """
    pass


@click.command(short_help="Assemble packets.")
def asm():
    """
    Assembles plain text packets description back into binary.

    Example use:

    \b
    kit.py asm
        packets.txt
        -o packets.bin
    """
    pass


@click.command(short_help="Pack replay.")
def pack():
    """
    Packs all the parts back into consistent replay.

    Example use:

    \b
    kit.py pack
        -1 first.json
        -2 second.json
        -p packets.bin
        -o 20140810_1853_usa-M18_Hellcat_28_desert.wotreplay
    """
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

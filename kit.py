import binascii
import json
import logging
import struct
import sys
import zlib

import click


class ReplayHeader:
    """Replay header tools."""

    HEADER = b"\x12\x32\x34\x11\x02\x00\x00\x00"

    @classmethod
    def read(cls, replay):
        """Reads replay header."""
        logging.debug("Reading header...")
        header = replay.read(len(cls.HEADER))
        logging.debug("Header: %s.", binascii.hexlify(header))
        if header != cls.HEADER:
            logging.warning("Header mismatch.")
        json_block_count = header[4]
        logging.debug("JSON block count: %d.", json_block_count)
        if json_block_count not in (1, 2):
            logging.warning("Invalid JSON block count.")
        return json_block_count


class ReplayJson:
    """Replay JSON tools."""

    LENGTH_STRUCT = struct.Struct("<i")
    ENCODING = "ascii"

    @classmethod
    def read(cls, replay):
        """Reads JSON from replay."""
        logging.debug("Reading JSON...")
        length = cls.LENGTH_STRUCT.unpack(replay.read(cls.LENGTH_STRUCT.size))[0]
        logging.debug("JSON length: %d.", length)
        return json.loads(replay.read(length).decode(cls.ENCODING))


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
    json_block_count = ReplayHeader.read(replay)
    json.dump(ReplayJson.read(replay), first, indent=2)
    if json_block_count == 2:
        json.dump(ReplayJson.read(replay), second, indent=2)


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

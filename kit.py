import binascii
import json
import logging
import operator
import struct
import sys
import zlib

import click

import blowfish


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


class LengthMixin:
    """Length mixin."""

    STRUCT = struct.Struct("<i")

    @classmethod
    def read_length(cls, replay):
        length = cls.STRUCT.unpack(replay.read(cls.STRUCT.size))[0]
        logging.debug("Length: %d.", length)
        return length


class ReplayJson(LengthMixin):
    """Replay JSON tools."""

    ENCODING = "ascii"

    @classmethod
    def read(cls, replay):
        """Reads JSON from replay."""
        logging.debug("Reading JSON...")
        length = cls.read_length(replay)
        return json.loads(replay.read(length).decode(cls.ENCODING))


class ReplayEncryptedPart(LengthMixin):
    """Encrypted part tools."""

    BLOCK_LENGTH = 8
    CIPHER = blowfish.Blowfish(b"\xDE\x72\xBE\xA0\xDE\x04\xBE\xB1\xDE\xFE\xBE\xEF\xDE\xAD\xBE\xEF")

    @classmethod
    def read(cls, replay):
        logging.debug("Reading encrypted part...")
        length = cls.read_length(replay)
        logging.debug("Decrypting...")
        blocks = []
        previous_block = bytes(8)
        while True:
            block = replay.read(cls.BLOCK_LENGTH)
            if not block:
                break
            block = cls.CIPHER.decrypt(block)
            block = bytes(map(operator.xor, block, previous_block))
            previous_block = block
            blocks.append(block)
        compressed_data = b"".join(blocks)[:length]
        logging.debug("Decompressing...")
        uncompressed_data = zlib.decompress(compressed_data)
        logging.debug("Uncompressed data length: %d.", len(uncompressed_data))
        return uncompressed_data


@click.command(short_help="Unpack replay.")
@click.argument("replay", type=click.File("rb"))
@click.option("-1", "--first", help="First JSON part output.", required=True, type=click.File("wt"))
@click.option("-2", "--second", help="Second JSON part output.", required=True, type=click.File("wt"))
@click.option("-p", "--packets", help="Packets output.", required=True, type=click.File("wb"))
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
    magic = replay.read(4)
    logging.debug("Magic: %s.", binascii.hexlify(magic))
    data = ReplayEncryptedPart.read(replay)
    packets.write(data)


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

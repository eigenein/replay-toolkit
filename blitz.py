#!/usr/bin/env python3
# coding: utf-8

import collections
import logging
import struct
import sys

import click


@click.group()
def main():
    """
    WoT Blitz replay unpacker.
    """
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
        stream=sys.stderr,
    )


@main.command(short_help="Disassemble replay.")
@click.argument("replay", type=click.File("rb"))
def dis(replay):
    with BinaryReader(replay) as binary_reader, ReplayReader(binary_reader) as replay_reader:
        replay_header = replay_reader.read_header()
        logging.info("Header: %s", replay_header)


class BinaryReader:
    """
    Used to read a binary file.
    """

    UNSIGNED_INT_STRUCT = struct.Struct("<I")

    def __init__(self, file):
        self.file = file

    def read_unsigned_int(self):
        return self.read_struct(self.UNSIGNED_INT_STRUCT)[0]

    def read_struct(self, struct_object: struct.Struct):
        """
        Reads struct from the file.
        """
        return struct_object.unpack(self.file.read(struct_object.size))

    def __enter__(self):
        self.file.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.__exit__(exc_type, exc_val, exc_tb)


class ReplayReader:
    """
    Used to read a replay file.
    """

    def __init__(self, binary_reader: BinaryReader):
        self.binary_reader = binary_reader

    def read_header(self):
        """
        Reads replay header.
        """
        magic = self.binary_reader.read_unsigned_int()
        size = self.binary_reader.read_unsigned_int()
        return ReplayHeader(
            magic=magic,
            size=size,
        )

    def __enter__(self):
        self.binary_reader.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.binary_reader.__exit__(exc_type, exc_val, exc_tb)


ReplayHeader = collections.namedtuple("ReplayHeader", "magic size")


if __name__ == "__main__":
    main()

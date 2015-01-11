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
    with BinaryReader(replay, "Windows-1251") as binary_reader, ReplayReader(binary_reader) as replay_reader:
        replay_header = replay_reader.read_header()
        logging.info("Header: %s", replay_header)


class BinaryReader:
    """
    Used to read a binary file.
    """

    UNSIGNED_INT_STRUCT = struct.Struct("<I")

    def __init__(self, file, encoding):
        self.file = file
        self.encoding = encoding

    def read_bytes(self, count: int) -> bytes:
        return self.file.read(count)

    def read_unsigned_int(self) -> int:
        return self.read_struct(self.UNSIGNED_INT_STRUCT)[0]

    def read_string(self) -> str:
        length = self.read_unsigned_int()
        return self.read_bytes(length).decode(encoding=self.encoding)

    def read_struct(self, struct_object: struct.Struct) -> tuple:
        """
        Reads struct from the file.
        """
        return struct_object.unpack(self.file.read(struct_object.size))

    def __enter__(self):
        self.file.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.__exit__(exc_type, exc_val, exc_tb)


ReplayHeader = collections.namedtuple("ReplayHeader", "magic size unknown1 client_version")


class ReplayReader:
    """
    Used to read a replay file.
    """

    def __init__(self, binary_reader: BinaryReader):
        self.binary_reader = binary_reader

    def read_header(self) -> ReplayHeader:
        """
        Reads replay header.
        """
        magic = self.binary_reader.read_unsigned_int()
        size = self.binary_reader.read_unsigned_int()
        unknown1 = self.binary_reader.read_bytes(12)
        client_version = self.binary_reader.read_string()
        return ReplayHeader(
            magic=magic,
            size=size,
            unknown1=unknown1,
            client_version=client_version,
        )

    def __enter__(self):
        self.binary_reader.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.binary_reader.__exit__(exc_type, exc_val, exc_tb)


if __name__ == "__main__":
    main()

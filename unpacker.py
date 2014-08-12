#!/usr/bin/env python3
# coding: utf-8

import argparse
import binascii
import io
import json
import struct
import sys
import zlib

import blowfish


def unpack_int(payload):
    return struct.unpack("i", payload[0:4])[0]


def read_int(fp):
    return unpack_int(fp.read(4))


def read_json(replay):
    print("Reading JSON…")
    return json.loads(replay.read(read_int(replay)).decode("ascii"))


def read_packets(unpacked_replay):
    unpacked_replay.read(12)

    version_length = read_int(unpacked_replay)
    version = unpacked_replay.read(version_length).decode("ascii")
    print("Version: %s.", version)

    while True:
        packet = read_packet(unpacked_replay)
        if packet is None:
            break
        yield packet


def read_packet(unpacked_replay):
    payload_length = unpacked_replay.read(4)
    if not payload_length:
        return None
    payload_length = unpack_int(payload_length)

    packet_type = read_int(unpacked_replay)
    clock = read_int(unpacked_replay)
    payload = unpacked_replay.read(payload_length)

    packet = {
        "type": "%02x" % packet_type,
    }

    if packet_type in (0x07, 0x08):
        sub_type = packet["sub_type"] = "%02x" % unpack_int(payload[4:])

    if packet_type in (0x03, 0x05):
        packet["clock"] = clock
        packet["player_id"] = unpack_int(payload)
    elif packet_type == 0x0a:
        packet["clock"] = clock
        packet["player_id"] = unpack_int(payload)
        packet["position"] = struct.unpack("fff", payload[12:24])
        packet["hull_orientation"] = struct.unpack("fff", payload[36:48])
    elif packet_type == 0x07:
        packet["clock"] = clock
        packet["player_id"] = unpack_int(payload)
        if sub_type == 0x03:
            packet["health"] = struct.unpack("H", payload[12:14])
        elif sub_type == 0x07:
            # packet["destroyed_track_id"] = ...
            pass
    # elif ...
    else:
        packet["payload"] = binascii.hexlify(payload)
    
    return packet


def main(args):
    replay = args.replay

    print("Reading header…")
    header = replay.read(8)
    json_blocks_count = header[4]

    for i in range(json_blocks_count):
        read_json(replay)

    replay.read(4)
    length = read_int(replay)
    print("Compressed data length: %d." % length)

    cipher = blowfish.Blowfish(b"\xDE\x72\xBE\xA0\xDE\x04\xBE\xB1\xDE\xFE\xBE\xEF\xDE\xAD\xBE\xEF")
    previous_block = b"\x00" * 8
    blocks = []

    print("Decrypting…")
    while True:
        block = replay.read(8)
        if not block:
            break
        block = cipher.decrypt(block)
        block = bytes(byte1 ^ byte2 for byte1, byte2 in zip(block, previous_block))
        previous_block = block
        blocks.append(block)

    print("Blocks: %d." % len(blocks))
    compressed_data = b"".join(blocks)[:length]

    print("Decompressing…")
    uncompressed_data = zlib.decompress(compressed_data)

    print("Uncompressed data length: %d." % len(uncompressed_data))
    args.output.write(uncompressed_data)

    print("Reading packets…")
    for packet in read_packets(io.BytesIO(uncompressed_data)):
        print(packet, file=args.packets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="replay", metavar="REPLAY", type=argparse.FileType("rb"))
    parser.add_argument("-o", "--output", dest="output", metavar="OUTPUT", required=True, type=argparse.FileType("wb"))
    parser.add_argument("-p", "--packets", default=sys.stdout, dest="packets", metavar="PACKETS", type=argparse.FileType("wt"))
    main(parser.parse_args())

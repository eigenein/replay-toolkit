import binascii
import enum
import json
import logging
import operator
import struct
import sys
import zlib

import click

import blowfish


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
        previous_block = bytes(cls.BLOCK_LENGTH)
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


class ReplayPacketType(enum.Enum):
    """Replay packet type."""
    base_player_create = 0x00
    cell_player_create = 0x01
    entity_control = 0x02
    entity_enter = 0x03
    entity_leave = 0x04
    entity_create = 0x05
    entity_properties = 0x06
    entity_property = 0x07
    entity_method = 0x08
    entity_move = 0x09
    entity_move_with_error = 0x0A
    space_data = 0x0B
    space_gone = 0x0C
    stream_complete = 0x0D
    entities_reset = 0x0E
    restore_client = 0x0F
    enable_entities_rejected = 0x10
    client_ready = 0x11
    set_arena_period = 0x12
    set_arena_length = 0x13
    client_version = 0x14
    update_camera = 0x15
    update_gun_marker = 0x16
    change_control_mode = 0x17
    update_turret_yaw = 0x18
    update_gun_pitch = 0x19
    ammo_button_pressed = 0x1A
    update_fps_ping_lag = 0x1B
    set_gun_reload_time = 0x1C
    set_active_consumable_slot = 0x1D
    set_player_vehicle_id = 0x1E
    battle_chat_message = 0x1F
    nested_entity_property = 0x20
    minimap_cell_clicked = 0x21
    update_camera2 = 0x22
    set_server_time = 0x23
    lock_target = 0x24
    set_cruise_mode = 0x25


class ReplayPropertyType(enum.Enum):
    """Replay packet property type."""
    player_id = 1
    health = 2
    source = 3
    target = 4
    position = 5
    hull_orientation = 6
    message = 7
    destroyed_track_id = 8
    alt_track_state = 9


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

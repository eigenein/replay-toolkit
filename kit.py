#!/usr/bin/env python3
# coding: utf-8

import binascii
import enum
import itertools
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
@click.option("-2", "--second", help="Second JSON part output.", required=True, type=click.File("wt", lazy=True))
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
    json.dump(Json.read(replay), first, indent=2)
    if json_block_count == 2:
        json.dump(Json.read(replay), second, indent=2)
    magic = replay.read(4)
    logging.info("Magic: %s.", binascii.hexlify(magic))
    data = Encryptor.read(replay)
    packets.write(data)


@click.command(short_help="Pack replay.")
@click.option("-1", "--first", help="First JSON part.", required=True, type=click.File("rt"))
@click.option("-2", "--second", help="Second JSON part.", required=False, type=click.File("rt"))
@click.option("-p", "--packets", help="Packets binary input..", required=True, type=click.File("rb"))
@click.option("-o", "--output", help="Output replay file.", required=True, type=click.File("wb"))
def pack(first, second, packets, output):
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

    ReplayHeader.write(output, 2 if second else 1)
    Json.write(output, json.load(first))
    if second:
        Json.write(output, json.load(second))
    output.write(b"\xaa\xc6\x31\x00")  # magic
    data = packets.read()
    Encryptor.write(output, data)


class ReplayHeader:
    """Replay header tools."""

    HEADER = b"\x12\x32\x34\x11\x02\x00\x00\x00"

    @classmethod
    def read(cls, replay):
        """Reads replay header."""
        logging.info("Reading header...")
        header = replay.read(len(cls.HEADER))
        logging.info("Header: %s.", binascii.hexlify(header))
        if (header[:4] != cls.HEADER[:4]) or (header[5:] != cls.HEADER[5:]):
            logging.warning("Header mismatch.")
        json_block_count = header[4]
        logging.info("JSON block count: %d.", json_block_count)
        if json_block_count not in (1, 2):
            logging.warning("Invalid JSON block count.")
        return json_block_count

    @classmethod
    def write(cls, output, json_block_count):
        """Writes replay header."""
        logging.info("Writing header...")
        header = bytearray(cls.HEADER)
        header[4] = json_block_count
        output.write(bytes(header))


class LengthMixin:
    """Length mixin."""

    LENGTH_STRUCT = struct.Struct("<i")

    @classmethod
    def read_length(cls, fp):
        buffer = fp.read(cls.LENGTH_STRUCT.size)
        if not buffer:
            raise StopIteration()
        length = cls.LENGTH_STRUCT.unpack(buffer)[0]
        return length

    @classmethod
    def write_length(cls, fp, length):
        fp.write(cls.LENGTH_STRUCT.pack(length))


class Json(LengthMixin):
    """Replay JSON tools."""

    ENCODING = "ascii"

    @classmethod
    def read(cls, replay):
        """Reads JSON from replay."""
        logging.info("Reading JSON...")
        length = cls.read_length(replay)
        return json.loads(replay.read(length).decode(cls.ENCODING))

    @classmethod
    def write(cls, output, obj):
        """Writes JSON to replay."""
        logging.info("Writing JSON...")
        value = json.dumps(obj).encode(cls.ENCODING)
        cls.write_length(output, len(value))
        output.write(value)


class Encryptor(LengthMixin):
    """Encrypted part tools."""

    BLOCK_LENGTH = 8
    CIPHER = blowfish.Blowfish(b"\xDE\x72\xBE\xA0\xDE\x04\xBE\xB1\xDE\xFE\xBE\xEF\xDE\xAD\xBE\xEF")

    @classmethod
    def read(cls, replay):
        logging.info("Reading encrypted part...")
        length = cls.read_length(replay)
        logging.info("Decrypting...")
        blocks = []
        previous_block = bytes(cls.BLOCK_LENGTH)
        while True:
            block = replay.read(cls.BLOCK_LENGTH)
            if not block:
                break
            block = cls.CIPHER.decrypt(block)
            block = cls.xor_blocks(block, previous_block)
            previous_block = block
            blocks.append(block)
        compressed_data = b"".join(blocks)[:length]
        logging.info("Decompressing...")
        uncompressed_data = zlib.decompress(compressed_data)
        logging.info("Uncompressed data length: %d.", len(uncompressed_data))
        return uncompressed_data

    @classmethod
    def write(cls, output, data):
        # Compress.
        logging.info("Compressing...")
        compressed_data = zlib.compress(data)
        # Write length.
        compressed_length = len(compressed_data)
        cls.write_length(output, compressed_length)
        # Align.
        tail_length = compressed_length % 8
        if tail_length:
            compressed_data += bytes(8 - tail_length)
        # Encrypt and write.
        logging.info("Encrypting...")
        previous_block = bytes(cls.BLOCK_LENGTH)
        for offset in range(0, len(compressed_data), cls.BLOCK_LENGTH):
            unencrypted_block = compressed_data[offset:(offset + cls.BLOCK_LENGTH)]
            block = cls.xor_blocks(unencrypted_block, previous_block)
            previous_block = unencrypted_block
            block = cls.CIPHER.encrypt(block)
            output.write(block)

    @classmethod
    def xor_blocks(cls, block1, block2):
        return bytes(map(operator.xor, block1, block2))


@click.command(short_help="Disassemble into packets.")
@click.argument("packets", type=click.File("rb"))
@click.option("-o", "--output", help="Disassembled output.", required=True, type=click.File("wt", encoding="utf-8"))
def dis(packets, output):
    """
    Disassembles binary packets part into plain text packets description.

    Output format is sequence of packet descriptions:

    \b
    clock packet_type
    payload
    \b
        offset property_type value [value [value ...]]
        offset property_type value [value [value ...]]
        ...
    end

    Example use:

    \b
    kit.py dis
        packets.bin
        -o packets.txt
    """
    for packet_count in itertools.count(0):
        try:
            packet_type, subtype, clock, payload = PacketAssembler.read_packet(packets)
        except StopIteration:
            break
        # Begin packet.
        print("begin {0.name}".format(packet_type), file=output)
        print(binascii.hexlify(payload).decode("ascii"), file=output)
        print(file=output)
        # Print properties.
        for property_type in PacketAssembler.get_properties(packet_type, subtype):
            offset = PacketAssembler.get_property_offset(property_type, subtype)
            values = PacketAssembler.get_property_serializer(property_type).deserialize(payload, offset)
            print("{0:4d} {1.name} {2}".format(offset, property_type, " ".join(map(str, values))), file=output)
        # End packet.
        print("end", file=output)
        print(file=output)
    logging.info("Done. %d packets.", packet_count)


@click.command(short_help="Assemble packets.")
@click.argument("source", type=click.File("rt", encoding="utf-8"))
@click.option("-o", "--output", help="Assembled output.", required=True, type=click.File("wb"))
def asm(source, output):
    """
    Assembles plain text packets description back into binary.

    Example use:

    \b
    kit.py asm
        packets.txt
        -o packets.bin
    """

    state = AssemblerState.initial
    packet_count = 0

    for i, line in enumerate(source, start=1):
        line = line.strip()
        if not line:
            continue

        if state == AssemblerState.initial:
            begin, packet_type = line.split()
            if begin != "begin":
                raise ValueError(begin)
            packet_type = PacketType[packet_type]
            state = AssemblerState.begin

        elif state == AssemblerState.begin:
            payload = bytearray(binascii.unhexlify(line.encode("ascii")))
            state = AssemblerState.properties

        elif line != "end":
            offset, property_type, values = line.split(maxsplit=2)
            offset = int(offset)
            property_type = PropertyType[property_type]
            values = values.split() if property_type != PropertyType.message else [values]
            PacketAssembler.set_property(payload, property_type, offset, values)

        else:
            PacketAssembler.write_packet(output, packet_type, bytes(payload))
            packet_count += 1
            state = AssemblerState.initial

    if state != AssemblerState.initial:
        raise ValueError(state)

    logging.info("Done. %d packets.", packet_count)


class AssemblerState:
    initial = 0
    begin = 1
    properties = 2


class PacketType(enum.Enum):
    """Replay packet type."""
    unknown_last = -1
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
    unknown_39 = 39
    unknown_40 = 40


class PropertyType(enum.Enum):
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
    clock = 10
    subtype = 11
    fps = 12
    ping = 13
    lag = 14


class PropertySerializer:
    """Serializes and deserializes property value."""

    def deserialize(self, payload, offset):
        raise NotImplementedError()

    def serialize(self, values):
        raise NotImplementedError()

    def cast(self, value):
        return value


class StructPropertySerializer(PropertySerializer):
    """Struct serializer."""

    def __init__(self, fmt, type):
        self.struct = struct.Struct(fmt)
        self.type = type

    def deserialize(self, payload, offset):
        return self.struct.unpack(payload[offset:(offset + self.struct.size)])

    def serialize(self, values):
        return self.struct.pack(*values)

    def cast(self, value):
        """Casts value to serializer specific type."""
        return self.type(value)

    def __repr__(self):
        return "{0.__class__.__name__}(type={0.type})".format(self)


class MessageSerializer(PropertySerializer, LengthMixin):
    """Battle chat message serializer."""

    ENCODING = "utf-8"

    def deserialize(self, payload, offset):
        length = self.LENGTH_STRUCT.unpack(payload[offset:(offset + 4)])[0]
        return (payload[(offset + 4):][:length].decode(self.ENCODING), )

    def serialize(self, values):
        (value, ) = values
        value = value.encode(self.ENCODING)
        return self.LENGTH_STRUCT.pack(len(value)) + value


class PacketAssembler(LengthMixin):
    """Reads properties of packet."""

    # Packet header structs.
    PACKET_TYPE_STRUCT = struct.Struct("<i")
    CLOCK_STRUCT = struct.Struct("<f")

    # Property serializers.
    CLOCK_SERIALIZER = StructPropertySerializer("<f", float)
    INT_SERIALIZER = StructPropertySerializer("<i", int)
    POSITION_SERIALIZER = StructPropertySerializer("<fff", float)
    SHORT_SERIALIZER = StructPropertySerializer("<H", int)
    MESSAGE_SERIALIZER = MessageSerializer()
    BYTE_SERIALIZER = StructPropertySerializer("<B", int)

    @classmethod
    def read_packet(cls, packets):
        """Reads packet from input file."""
        payload_length = cls.read_length(packets)
        packet_type = cls.PACKET_TYPE_STRUCT.unpack(packets.read(cls.PACKET_TYPE_STRUCT.size))[0]
        packet_type = PacketType(packet_type)
        payload = packets.read(payload_length + 4)
        clock = cls.CLOCK_STRUCT.unpack(payload[0:4])[0]
        subtype = None
        if packet_type in (PacketType.entity_property, PacketType.entity_method):
            subtype = cls.PACKET_TYPE_STRUCT.unpack(payload[8:12])[0]
        return packet_type, subtype, clock, payload

    @classmethod
    def get_properties(cls, packet_type, subtype):
        """Gets property types for packet type and subtype."""
        yield PropertyType.clock
        if packet_type in (PacketType.entity_enter, PacketType.entity_create):
            yield PropertyType.player_id
        elif packet_type == PacketType.entity_move_with_error:
            yield PropertyType.player_id
            yield PropertyType.position
            yield PropertyType.hull_orientation
        elif packet_type == PacketType.entity_property:
            yield PropertyType.player_id
            yield PropertyType.subtype
            if subtype == 0x03:
                yield PropertyType.health
            # TODO: elif subtype == 0x07:
            # TODO:    yield PropertyType.destroyed_track_id
        elif packet_type == PacketType.entity_method:
            yield PropertyType.player_id
            yield PropertyType.subtype
            # TODO: property_t::tank_destroyed
            if subtype == 0x01:
                yield PropertyType.source
                yield PropertyType.health
            elif subtype == 0x05:
                yield PropertyType.source
            elif subtype == 0x0B:
                yield PropertyType.source
                yield PropertyType.target
            elif subtype == 0x17:
                yield PropertyType.target
        elif packet_type == PacketType.battle_chat_message:
            yield PropertyType.message
        elif packet_type == PacketType.nested_entity_property:
            yield PropertyType.player_id
        elif packet_type == PacketType.update_fps_ping_lag:
            yield PropertyType.fps
            yield PropertyType.ping
            yield PropertyType.lag
            # TODO: property_t::destroyed_track_id
            # TODO: property_t::alt_track_state

    @classmethod
    def get_property_offset(cls, property_type, packet_subtype):
        """Gets property offset for specified property type and packet subtype."""
        if property_type == PropertyType.clock:
            return 0
        if property_type == PropertyType.subtype:
            return 8
        if property_type == PropertyType.health:
            return 16
        if property_type == PropertyType.hull_orientation:
            return 40
        if property_type == PropertyType.message:
            return 4
        if property_type == PropertyType.player_id:
            return 4
        if property_type == PropertyType.position:
            return 16
        if property_type == PropertyType.source:
            return 18 if packet_subtype == 0x01 else (22 if packet_subtype == 0x0B else 16)
        if property_type == PropertyType.target:
            return 20 if packet_subtype == 0x17 else 16
        if property_type == PropertyType.fps:
            return 4
        if property_type == PropertyType.ping:
            return 5
        if property_type == PropertyType.lag:
            return 7
        raise ValueError((property_type, packet_subtype))
        # TODO: PropertyType.AltTrackState
        # TODO: PropertyType.DestroyedTrackId

    @classmethod
    def get_property_serializer(cls, property_type):
        """Gets serializer for specified property type."""
        if property_type == PropertyType.clock:
            return cls.CLOCK_SERIALIZER
        if property_type in (PropertyType.player_id, PropertyType.source, PropertyType.target, PropertyType.subtype):
            return cls.INT_SERIALIZER
        if property_type in (PropertyType.hull_orientation, PropertyType.position):
            return cls.POSITION_SERIALIZER
        if property_type in (PropertyType.health, PropertyType.ping):
            return cls.SHORT_SERIALIZER
        if property_type == PropertyType.message:
            return cls.MESSAGE_SERIALIZER
        if property_type in (PropertyType.fps, PropertyType.lag):
            return cls.BYTE_SERIALIZER
        raise ValueError(property_type)

    @classmethod
    def set_property(cls, payload, property_type, offset, values):
        """Sets property value on payload."""
        serializer = cls.get_property_serializer(property_type)
        replacement = serializer.serialize(tuple(map(serializer.cast, values)))
        payload[offset:(offset + len(replacement))] = replacement

    @classmethod
    def write_packet(cls, output, packet_type, payload):
        """Writes packet to output file."""
        cls.write_length(output, len(payload) - 4)
        output.write(cls.PACKET_TYPE_STRUCT.pack(packet_type.value))
        output.write(payload)


@click.group()
def main():
    """
    World of Tanks Replay Toolkit.

    Use `unpack` command followed by `dis` command to unpack replay into sequence of packets.

    Use `asm` command followed by `pack` command to pack sequence of packets back into replay.
    """
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
        stream=sys.stderr,
    )


main.add_command(unpack)
main.add_command(dis)
main.add_command(asm)
main.add_command(pack)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# coding: utf-8

import struct
import pickle

replay = open("20141222_0017_GB13_FV215b_karelia.wotreplay", 'rb')
replay.read(4)
header1 = replay.read(4)
header1 = struct.unpack('i', header1)
print(header1)
replay.read(12)
lenght_version = replay.read(4)
lenght_version = struct.unpack('i', lenght_version)
version = replay.read(lenght_version[0])
print(version)
replay.read(13)
header2 = replay.read(8)
header2 = struct.unpack('q', header2)
print(header2)
replay.read(header2[0])


replay.read(30)
len_pick = replay.read(2)
replay.read(1)  # ни к чему не имеет отношения
len_pick = struct.unpack('h', len_pick)
print(len_pick)
pick_list_nick = replay.read(len_pick[0])
f1 = open("pick.txt", 'wb')
f1.write(pick_list_nick)
print(pick_list_nick[-1])
list_nick = pickle.loads(pick_list_nick, encoding="cp866")
for tup in list_nick:
	print(tup[2])
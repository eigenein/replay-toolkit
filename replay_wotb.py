#!/usr/bin/env python3
# coding: utf-8

import struct
import pickle

replay = open("20141221_2203_T-54_fort.wotreplay", 'rb')
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

print(list_nick)  # вывод ушей

replay.read(25) # не знаю зачем именно 25

len_pick = replay.read(1)  # длина второго запикленного пакета
len_pick = struct.unpack('b', len_pick)
pickle_data = replay.read(len_pick[0])
pickle_data = pickle.loads(pickle_data, encoding="cp866")
print(pickle_data)  # вывод второго запикленного пакета

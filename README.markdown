# World of Tanks Replay Toolkit

## Распаковка

Полная распаковка реплея делается в два этапа.

Сначала реплей разбивается на два JSON'а и расшифрованный дамп с пакетами:

```
python kit.py unpack -1 first.json -2 second.json -p packets.bin Replay-exploit.wotreplay
```

Если не нужен, например, JSON, то в Windows можно вместо файла передать NUL:

```
python kit.py unpack b.wotreplay -1 NUL -2 NUL -p b.bin
```

Затем, дамп с пакетами можно перевести в листинг с текстовым описанием типов и некоторых полей пакетов:

```
python kit.py dis packets.bin -o packets.txt
```

## Формат листинга

TODO

## Редактирование

TODO

## Упаковка

TODO
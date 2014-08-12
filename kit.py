import json

import click


@click.command(help="unpack replay")
def unpack():
    pass


@click.command(help="disassemble into packets")
def dis():
    pass


@click.command(help="assemble packets")
def asm():
    pass


@click.command(help="pack replay")
def pack():
    pass


@click.group()
def main():
    pass


main.add_command(unpack)
main.add_command(dis)
main.add_command(asm)
main.add_command(pack)


if __name__ == '__main__':
    main()

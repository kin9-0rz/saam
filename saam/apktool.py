import argparse
import subprocess

from . import APKTOOL_PATH


def decode(framework, output, apk_path, force, no_res=False):
    if framework:
        framework = ' -p ' + framework + ' '
    else:
        framework = ''

    if output:
        output = ' -o ' + output + ' '
    else:
        output = ''

    if force:
        force = ' -f '
    else:
        force = ''

    if no_res:
        no_res = ' -r '
    else:
        no_res = ''

    cmd = 'java -jar ' + APKTOOL_PATH + ' d ' + \
        force + no_res + framework + output + apk_path
    subprocess.call(cmd, shell=True)


def build(app_path, force=False, output=None, frame_path=None):
    force = ' -f ' if force else ''

    frame_path = ' -p ' + frame_path + ' ' if frame_path else ''

    if output:
        output = ' -o ' + output + ' '
    else:
        output = ''

    cmd = 'java -jar ' + APKTOOL_PATH + ' b ' + \
        force + output + frame_path + app_path

    print(cmd)
    subprocess.call(cmd, shell=True)


def main_decode(args):
    decode(args.p, args.o, args.file, args.f)


def main_build(args):
    print(args)
    build(args.p, args.o, args.file, args.f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='apktool',
        description='Apktool - a tool for reengineering Android apk files')

    subparser = parser.add_subparsers()

    # decode
    parser_d = subparser.add_parser('d', help='decode')
    parser_d.add_argument('-f', action='store_true',
                          help='force', required=False)
    parser_d.add_argument(
        '-o', help='The name of folder that gets written. Default is apk.out', required=False)
    parser_d.add_argument('-p', help='framework path', required=False)
    parser_d.add_argument('file', help='file')
    parser_d.set_defaults(func=main_decode)

    # build
    parser_b = subparser.add_parser('b', help='b')
    parser_b.add_argument('-f', action='store_true',
                          help='force', required=False)
    parser_b.add_argument(
        '-o', help='The name of folder that gets written. Default is apk.out', required=False)
    parser_b.add_argument('-p', help='framework path', required=False)
    parser_b.add_argument('file', help='file')
    parser_b.set_defaults(func=main_build)

    args = parser.parse_args()
    args.func(args)

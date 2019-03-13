import argparse
import configparser
import os.path
import subprocess
import sys

from cigam import Magic

# for path in sys.path:
#     if path != '' and path in __file__:
#         amas_path = path

# baksmali_path = os.path.join(amas_path, 'tools', 'smali', 'baksmali.jar')
# smali_path = os.path.join(amas_path, 'tools', 'smali', 'smali.jar')
# droidbox_framework = os.path.join(amas_path, 'tools', 'droidbox-framework')


cfg = configparser.ConfigParser()
print(cfg.sections())
print(cfg.read('conf.ini'))
print(cfg.sections())
apktool_path = cfg['decompiler']['apktool']


def baksmali(flag, file_path, framework=None, output=None):
    if framework:
        framework = ' -d ' + framework + ' '
    else:
        framework = ''

    if output:
        output = ' -o ' + output
    else:
        output = ''
    cmd = 'java -jar %s %s %s%s%s' %
        (baksmali_path, flag, framework, file_path, output)
    subprocess.call(cmd, shell=True)


def smali(target_dir, output=None):
    if output:
        output = ' -o ' + output
    else:
        output = ''
    cmd = 'java -jar %s a %s %s' % (smali_path, target_dir, output)
    subprocess.call(cmd, shell=True)


def odex2dex(input, output):
    import tempfile
    smali_tempdir = tempfile.mkdtemp()
    baksmali('x', input, droidbox_framework, smali_tempdir)
    smali(smali_tempdir, output)


def odex_to_dex(args):
    if not os.path.exists(args.file):
        print(args.file, 'is not exists.')
    elif os.path.isfile(args.file):
        file_type = Magic(args.file).get_type()
        if file_type == 'odex':
            odex2dex(args.file, args.o)
        else:
            print(file_type, 'unsupport')
    else:
        print('unsupported, please give a odex file.')


def disassembles(args):
    if not os.path.exists(args.file):
        print(args.file, 'is not exists.')
    elif os.path.isfile(args.file):
        file_type = Magic(args.file).get_type()
        if file_type in ['dex', 'apk']:
            baksmali('d', args.file, output=args.o)
        elif file_type == 'odex':
            if args.p:
                baksmali('x', args.file, args.p, args.o)
            else:
                baksmali('x', args.file, droidbox_framework, args.o)
        else:
            print(file_type, 'unsupport')
    else:
        print('unsupported, please give a dex/odex/oat file.')


def assembles(args):
    if not os.path.exists(args.file):
        print(args.file, 'is not exists.')
    elif os.path.isdir(args.file):
        smali(args.file, args.o)
    else:
        print(args.file, 'unsupported, please give a smali fold.')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='decompiler', description='decompiler')
    subparser = parser.add_subparsers()

    parser_d = subparser.add_parser('d',
                                    help='Disassembles a dex file or deodexes an odex/oat file.')
    parser_d.add_argument('-o',
                          help='The name of folder that gets written. Default is out',
                          required=False)
    parser_d.add_argument('-p', help='framework path', required=False)
    parser_d.add_argument('file', help='dex/odex/oat file')
    parser_d.set_defaults(func=disassembles)

    parser_a = subparser.add_parser('a',
                                    help='Assembles smali files into a dex file.')
    parser_a.add_argument('file', help='smali directory.')
    parser_a.add_argument('-o',
                          help='The name/path of the dex file to write. (default: out.dex)',
                          required=False)
    parser_a.set_defaults(func=assembles)

    parser_o = subparser.add_parser('o', help='odex2dex')
    parser_o.add_argument('file', help='odex')
    parser_o.add_argument('-o',
                          help='The name/path of the dex file to write. (default: out.dex)',
                          required=False)
    parser_o.set_defaults(func=odex_to_dex)

    args = parser.parse_args()
    if args != argparse.Namespace():
        args.func(args)
    else:
        parser.parse_args(['-h'])

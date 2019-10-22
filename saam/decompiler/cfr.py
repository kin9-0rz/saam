# https://www.benf.org/other/cfr/
import subprocess

from .. import CFR_PATH

__version__ = '0.0.1'

# HOME = os.path.join(os.path.dirname(__file__), '..', '..')

# __cfg = configparser.ConfigParser()
# __cfg.read(os.path.join(HOME, 'conf.ini'))

# ../tools/apktool/apktool.jar


print(CFR_PATH)


def class2java(inputfile, output='java_codes'):
    """.class 文件转 .java文件

    Args:
        inputfile (TYPE): class或jar文件
        output (TYPE): 输出目录
    """
    cmd = 'java -jar {} {} --outputdir {}'.format(
        CFR_PATH, inputfile, output)
    subprocess.call(cmd, shell=True)


def main(args):
    inputfile = args.input
    outputdir = args.output
    class2java(inputfile, outputdir)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='class2java')
    subparser = parser.add_argument('input')
    subparser = parser.add_argument('-o', '--output', required=False)

    args = parser.parse_args()
    main(args)

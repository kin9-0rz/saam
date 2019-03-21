# 规则的写法
# 从目录加载规则文件
# 一个规则，一个文件
# 执行代码片段
# 手工编写，查杀代码比较好
# 封装几个匹配的接口

import argparse
import os

from apkutils import APK

DEBUG = False


def debug(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if result and DEBUG:
            print(*args)
            print(kwargs)
        return result
    return wrapper


class FileMatcher:
    pass


class DexMatcher:

    def __init__(self, apk: APK):
        self.strings = set(apk.get_strings())

    @debug
    def match(self, string, flag=False):
        """匹配字符串，字符串格式为16进制

        Args:
            string (str): 16进制字符串
            flag (bool, optional): 是否为正则表达式
        """
        if flag:
            return False
        else:
            return string in set(self.strings)

    @debug
    def matchs(self, strings, ratio=1.0, flag=False):
        """匹配一组字符串

        这组字符串命中百分之多少才算命中。

        Args:
            strings (TYPE): 16进制字符串
            ratio (float, optional): 命中百分比
            flag (bool, optional): 是否为正则表达式
        """
        if flag:
            return False
        else:
            count = 0
            total = len(strings)
            for item in strings:
                if item in self.strings:
                    count += 1

            return count / total >= ratio

    @debug
    def match_mtd():
        """TODO 指定的类/方法中，存在特定的字符串
        """
        pass


class Scanner:

    def __init__(self, rule_path):
        self.rules = []
        self._init_rules(rule_path)

    def _init_rules(self, path):
        """初始化规则

        Args:
            path (str): 规则存放目录
        """
        for root, _, fnames in os.walk(path):
            for name in fnames:
                rpath = os.path.join(root, name)
                self.rules.append(self.get_rule_data(rpath))

    @staticmethod
    def get_rule_data(path):
        with open(path, mode='r', encoding='utf-8') as f:
            return f.read()

    def scan(self, path):
        """扫描指定文件

        Args:
            path (str): 路径
        """
        from cigam import Magic
        apk = None
        if Magic(path).get_type() == 'apk':
            apk = APK(path)
        print(path, end=' ')
        loc = {}
        g = globals()
        if apk:
            g['dex'] = DexMatcher(apk)

        for rule in self.rules:
            try:
                exec(rule, g, loc)
            except Exception as e:
                print()
                continue

            if loc['RESULT']:
                print(loc['MalwareName'])


def main(args):
    global DEBUG
    if args.d:
        DEBUG = True
    scanner = Scanner("/Users/bin/Projects/saam/mrules")

    path = args.input
    if os.path.isdir(path):
        for root, _, fnames in os.walk(path):
            for name in fnames:
                scanner.scan(os.path.join(root, name))
    elif os.path.isfile(path):
        scanner.scan(path)
    else:
        print('Not exists.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='mscan', description='')
    parser.add_argument('input', help="file path")
    parser.add_argument('-d', action='store_true', help="DEBUG")
    parser.add_argument('-r', help='rules path')
    args = parser.parse_args()
    main(args)

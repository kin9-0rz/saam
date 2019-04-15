# 提取一批APK之间的共性
# 1. Manifest
# 2. Dex
# 3. 资源文件
# 4. 图片
# 5. 任意文件，片段
# 正则表达式
# 编写一个类似yara的工具，yara依赖的东西过多，不靠谱。
# 这个工具，不要求速度，只要求命中。
# - 规则具有可读性
# - 规则具有通用性
# 所有的字符串直接可以match
# Manifest.match('正则')
# Dex.match_string('正则')
# Dex.match_opcode('正则')
# Dex.match_tree(结构hash)
# 结构hash问题
#
# inapk, 支持单个APK，把所有的关键字符串都解析出来
# 支持多个APK
import binascii
import json
import os
import os.path
import re

from apkutils import APK
from cigam import Magic


class APK_Intersection:

    def __init__(self, apks):
        self.apks = apks

        permission_pattern1 = r'uses-permission\s+?.*?:name="([^"]+?)"'
        permission_pattern2 = r'android:permission="([^"]+?)"'
        self.perm1_matcher = re.compile(permission_pattern1)
        self.perm2_matcher = re.compile(permission_pattern2)

        action_pattern = r'action\s+?.*?:name="([^"]+?)"'
        self.action_matcher = re.compile(action_pattern)

    def get_permissions(self, mani):
        perms = set()
        iter = self.perm1_matcher.finditer(mani)
        for item in iter:
            perms.add(item.groups()[0])

        iter = self.perm2_matcher.finditer(mani)
        for item in iter:
            perms.add(item.groups()[0])
        return perms

    def get_actions(self, mani):
        actions = set()
        iter = self.action_matcher.finditer(mani)
        for item in iter:
            actions.add(item.groups()[0])
        return actions

    def serialize_xml(self, org_xml):
        _xml = re.sub(r'\n', ' ', org_xml)
        _xml = re.sub(r'"\s+?>', '">', _xml)
        _xml = re.sub(r'>\s+?<', '><', _xml)
        return _xml

    def common(self, one, two):
        import difflib
        from difflib import SequenceMatcher as SM
        s = SM(None, one, two)
        r = s.ratio()
        if r == 1.0:
            return one

        d = difflib.Differ()
        sss = ''
        for item in list(d.compare(one, two)):
            if item.startswith(' '):
                sss += item[2:]
            elif not sss.endswith('*'):
                sss += '*'
        return sss

    def intersect_manifest(self):
        flag = True  # 第一次
        aflag = True
        perms = set()
        actions = set()

        same = None
        for apk in self.apks:
            # TODO 注意，这个东西有可能是字典
            # mani = apk.get_manifest()

            # if not mani:
            #     continue
            # p = mani.get('uses-permission', [])  # TODO 还有其他地方可以获取权限
            # if flag:
            #     perms = APK_Intersection.get_permissions(p)
            #     flag = False
            # else:
            #     perms = perms & APK_Intersection.get_permissions(p)

            mani = apk.get_org_manifest()
            if not mani:
                print('not mani')
                continue
            mani = self.serialize_xml(mani)

            if flag:
                perms = self.get_permissions(mani)
                flag = False
            else:
                perms = perms & self.get_permissions(mani)

            if aflag:
                actions = self.get_actions(mani)
                aflag = False
            elif not actions:
                print(actions)
                actions = self.get_actions(mani)
            else:
                actions = actions & self.get_actions(mani)

            if not same:
                same = mani
            else:
                same = self.common(same, mani)

        print('perms =', json.dumps(sorted(perms), indent=4))
        print('actions =', json.dumps(sorted(actions), indent=4))
        if not same:
            return
        result = re.sub(r'"[^"]+?\*[^"]+?"', '"[^"]+?"', same)
        print('ptns =', [result])

    def intersect_dex_string(self):
        flag = True
        strings = set()
        for apk in self.apks:
            if flag:
                strings = set(apk.get_strings())
                flag = False
            else:
                strings = strings & set(apk.get_strings())

        print('strs = [')
        for item in sorted(strings):
            if len(item) < 3 or len(item) > 300:
                continue
            try:
                print("    '{}', # {}".format(item, binascii.unhexlify(item).decode(errors='ignore')))
            except Exception as e:
                print("#    '{}', # {}".format(item, binascii.unhexlify(item)))
                pass
        print(']')

    def intersect_dex_opcode(self):
        pass

    def intersect_arsc(self):
        pass

    def intersect_mf(self):
        pass

    def intersect_dex_tree(self):
        md5s = set()
        flag = True
        ftree = None
        for apk in self.apks:
            result = apk.get_trees()
            if flag:
                ftree = result
            if not result:
                continue

            if flag:
                md5s = result.keys()
                flag = False
            else:
                md5s = md5s & result.keys()

        print('tree_id_list = [')
        for md5 in md5s:
            print("    '{}',  # {}".format(md5, ftree.get(md5)))
        print(']')


def main(args):
    if os.path.isfile(args.file):
        if args.T:
            t = Magic(args.file).get_type()
            if t != 'apk':
                return
            trees = APK(args.file).get_trees()
            nodes = trees.get(args.T, [])
            for node in nodes:
                APK.pretty_print(node)
        else:
            return

    if not os.path.isdir(args.file):
        return

    apks = []
    for root, _, files in os.walk(args.file):
        for f in files:
            path = os.path.join(root, f)
            t = Magic(path).get_type()
            if t != 'apk':
                continue
            apks.append(APK(path))

    if not apks:
        return

    ai = APK_Intersection(apks)
    if args.m:
        ai.intersect_manifest()

    if args.s:
        ai.intersect_dex_string()  # TODO 相同的字符串太多了，反编译删除干扰的数据

    if args.t:
        ai.intersect_dex_tree()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='APK文件')
    parser.add_argument('-m', action='store_true', help='Manifest')
    parser.add_argument('-s', action='store_true', help='Dex string')
    parser.add_argument('-o', action='store_true', help='Dex opcode')
    parser.add_argument('-r', action='store_true', help='Resource')
    parser.add_argument('-t', action='store_true', help='结构')
    parser.add_argument('-T', help='根据节点md5，查找结构')

    main(parser.parse_args())

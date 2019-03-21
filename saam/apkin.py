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
import os
import os.path
import binascii

from apkutils import APK


class APK_Intersection:

    def __init__(self, apks):
        self.apks = apks

    def get_permissions(mobj):
        perms = set()
        for item in mobj:
            perm = item.get('@android:name', '')
            if perm:
                perms.add(perm)
            else:
                print('KeyError:')
                print(item)
        return perms

    def intersect_manifest(self):
        print('Manifest')
        print('Permissions')
        flag = True
        perms = set()
        for apk in self.apks:
            # 注意，这个东西有可能是字典
            p = apk.get_manifest().get('uses-permission', [])
            if flag:
                perms = APK_Intersection.get_permissions(p)
                flag = False
            else:
                perms = perms & APK_Intersection.get_permissions(p)

        for item in sorted(perms):
            print(item)

    def intersect_dex_string(self):
        flag = True
        strings = set()
        for apk in self.apks:
            if flag:
                strings = set(apk.get_strings())
                flag = False
            else:
                strings = strings & set(apk.get_strings())

        for item in sorted(strings):
            if len(item) < 3:
                continue
            print("'{}', # {}".format(item, binascii.unhexlify(item).decode(errors='ignore')))

    def intersect_dex_opcode(self):
        pass

    def intersect_arsc(self):
        pass

    def intersect_mf(self):
        pass


def main(args):
    if not os.path.isdir(args.file):
        return

    from cigam import Magic
    # cigam.Magic()
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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='')
    parser.add_argument('-m', action='store_true', help='')
    parser.add_argument('-s', action='store_true', help='')
    parser.add_argument('-o', action='store_true', help='')
    parser.add_argument('-r', action='store_true', help='')

    main(parser.parse_args())

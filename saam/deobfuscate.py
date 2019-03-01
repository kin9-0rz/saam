import argparse
import os

from smafile import SmaliDir

from . import apktool


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def deobfuscate(sdir):
    print('deobfuscate...', sdir)
    if not os.path.exists(sdir):
        return

    smali_dir = SmaliDir(sdir, include=None, exclude=None)

    # old_clzs = []
    # old_mtds = []
    counter = 0

    print('classes ... ', end='')
    clzes = {}
    for sf in smali_dir:
        desc = sf.get_class()
        if is_ascii(desc):
            continue
        if '$' in desc:
            continue
        # 如果类名存在/
        if '/' in desc:
            new_desc = desc[:desc.rindex('/') + 1] + 'Clazz{};'.format(counter)
        else:
            new_desc = 'LClazz{};'.format(counter)
        smali_dir.update_desc(desc, new_desc)
        clzes[desc] = new_desc
        counter += 1
    print(counter)

    print('inner classes ... ', end='')

    counter = 0
    for sf in smali_dir:
        desc = sf.get_class()
        if is_ascii(desc):
            continue
        if '$' not in desc:
            continue
        arr = desc.split('$')
        # 只处理只有一个$号的类
        # TODO 子类的子类，暂时不处理
        if len(arr) != 2:
            continue
        key = arr[0] + ';'
        if key not in clzes:
            print('Not found ' + key)
            continue

        name = '${}'.format(arr[1])
        new_desc = clzes[key][:-1] + name
        if not is_ascii(name):
            new_desc = clzes[key][:-1] + '$InnerClass{};'.format(counter)
            counter += 1
        smali_dir.update_desc(desc, new_desc)

    print(counter)

    print('methods ... ', end='')
    counter = 0
    for sf in smali_dir:
        for sm in sf.get_methods():
            name = sm.get_name()
            if is_ascii(name):
                continue
            desc = sm.get_desc()
            sm.set_name('mtd{}'.format(counter))
            smali_dir.update_desc(desc, sm.get_desc())
            counter += 1
    print(counter)

    print('fields ... ', end='')
    counter = 0
    for sf in smali_dir:
        for sfield in sf.get_fields():
            name = sfield.get_name()
            if is_ascii(name):
                continue
            desc = sfield.get_desc()
            sfield.set_name('field{}'.format(counter))
            smali_dir.update_desc(desc, sfield.get_desc())
            counter += 1
    print(counter)


def run(args):
    output = 'detmp'
    apktool.decode(framework=None, output=output,
                   apk_path=args.apk, force=False, no_res=True)

    deobfuscate(os.path.join(output, 'smali'))

    apktool.build(app_path=output, force=True, output='de-' +
                  args.apk, frame_path=None)
    import shutil
    shutil.rmtree('detmp')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='deobfuscate',
        description='反混淆类名、方法名、变量名')

    parser.add_argument('apk', help='a apk file')

    args = parser.parse_args()
    run(args)

import argparse
import json
import os
import re
import sys

import cmd2
import pyadb3
from apkutils import APK
from cmd2 import Cmd, argparse_completer, with_argparser
from colorclass.color import Color
from graphviz import Digraph
from smafile import SmaliDir

from . import RISKS, apktool

notes = []
classes = set()

recursion_times = 0
recursion_limit = 100


class CmdLineApp(Cmd):

    sdcard = '/storage/sdcard0/'
    maps = None

    def __init__(self, file_path):
        Cmd.__init__(self)
        self.prompt = 'saam > '

        self.shortcuts.remove(('@', 'load'))
        self.shortcuts.append(('@', 'adb_cmd'))
        self.shortcuts.remove(('@@', '_relative_load'))
        self.shortcuts.append(('$', 'adb_shell_cmd'))
        self.shortcuts.append(('qc', 'quit_and_clean'))

        self.apk_path = file_path
        self.apk = APK(self.apk_path)
        self.apk_out = os.path.basename(file_path) + ".out"
        self.smali_files = None
        self.smali_dir = None
        self.adb = None
        self.smali_method_descs = []
        self.java_files = []

        vsmali_action = CmdLineApp.vsmali_parser.add_argument(
            'sfile', help='smali file path')
        setattr(vsmali_action, argparse_completer.ACTION_ARG_CHOICES,
                ('delimiter_complete',
                 {'delimiter': '/',
                  'match_against': self.smali_method_descs}))

        vjava_action = CmdLineApp.vjava_parser.add_argument(
            'jfile', help='java file path')
        setattr(vjava_action, argparse_completer.ACTION_ARG_CHOICES,
                ('delimiter_complete',
                 {'delimiter': '/',
                  'match_against': self.java_files}))

    def do_quit_and_clean(self, arg):
        import shutil
        shutil.rmtree(self.apk_out)

        self._should_quit = True
        return self._STOP_AND_EXIT

    # ------------------- Hardware And System  ---------------------
    def do_devinfos(self, arg):
        '''
        显示设备硬件信息
        '''
        cmd = 'getprop ro.product.brand'
        print('Brand  :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.product.model'
        print('Model  :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.product.device'
        print('Device :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.product.cpu.abi'
        print('CPU    :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop persist.radio.imei'
        print('IMEI   :', self.adb.run_shell_cmd(cmd).decode())

    def do_osinfos(self):
        '''显示设备系统信息'''
        cmd = 'getprop ro.build.description'
        print('Build Desc    :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.build.date'
        print('Build Data    :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.build.version.release'
        print('Build Version :', self.adb.run_shell_cmd(cmd)[:-1].decode())
        cmd = 'getprop ro.build.version.sdk'
        print('SDK Version   :', self.adb.run_shell_cmd(cmd)[:-1].decode())

    # ---------------------- Manifest -------------------------
    @staticmethod
    def serialize_xml(org_xml):
        import xmlformatter
        import xml
        # org_xml = re.sub(r'>[^<]+<', '><', org_xml)

        try:
            formatter = xmlformatter.Formatter()
            return formatter.format_string(org_xml).decode('utf-8')
        except xml.parsers.expat.ExpatError:
            return org_xml

    def do_manifest(self, arg):
        '''显示清单信息'''
        # TODO 清单的显示形式更改
        # 1. 分类显示，简单，默认
        # 2. 原始XML的方式，有可能显示超过页面，需要使用more的方式。
        org_xml = self.apk.get_org_manifest()
        if org_xml:
            print(self.serialize_xml(org_xml))

    def get_package(self):
        return self.apk.get_manifest()['@package']

    def get_main_activity(self):
        try:
            activities = self.apk.get_manifest()['application']['activity']
        except KeyError:
            return None

        if not isinstance(activities, list):
            activities = [activities]

        for item in activities:
            content = json.dumps(item)
            if 'android.intent.action.MAIN' in content\
                    and 'android.intent.category.LAUNCHER' in content:
                return item['@android:name']

        return None

    def do_receiver(self, arg):
        try:
            receivers = self.apk.get_manifest()['application']['receiver']
        except KeyError:
            return None
        print(json.dumps(receivers, indent=4, sort_keys=True))

    def do_activity(self, arg):
        try:
            receivers = self.apk.get_manifest()['application']['activity']
        except KeyError:
            return None
        print(json.dumps(receivers, indent=4, sort_keys=True))

    def do_service(self, arg):
        try:
            receivers = self.apk.get_manifest()['application']['service']
        except KeyError:
            return None
        print(json.dumps(receivers, indent=4, sort_keys=True))

    def show_risk_children(self, flag=False):
        result = ''
        pflag = True
        self.apk.get_files().sort(key=lambda k: (k.get('type'), k.get('name')))
        for item in self.apk.get_files():
            if flag:
                print(item.get('type'), item.get('name'))
                continue

            if item.get('type') not in ['dex', 'apk', 'elf']:
                continue

            if pflag:
                result = Color.red('\n===== Risk Files =====\n')
                pflag = False

            result += item.get('type') + ' ' + item.get('name') + '\n'

        return result

    children_parser = argparse.ArgumentParser()
    children_parser.add_argument('-a', '--all', action='store_true')

    @with_argparser(children_parser)
    def do_children(self, args):
        '''
        列出APK中的特殊文件
        '''
        self.apk.get_files().sort(key=lambda k: (k.get('type'), k.get('name')))
        for item in self.apk.get_files():
            if args.all:
                print(item.get('type'), item.get('name'))
                continue

            if item.get('type') in ['dex', 'apk', 'elf']:
                print(item.get('type'), item.get('name'))

    # ------------------- Static Analysis -------------------------
    # TODO 默认使用了apktool反编译
    # 转化为jar文件/默认解压为.class文件，cfr反编译工具会自行处理。
    def do_decompile(self, arg):
        '''
        使用apktool反编译apk, 默认初始化清单相关的包。

        '''
        pkgs = self.find_pkg_refx_manifest(self.apk.get_org_manifest())

        apktool.decode(None, self.apk_out, self.apk_path, True)
        for item in os.listdir(self.apk_out):
            if not item.startswith('smali'):
                continue

            self.smali_dir = SmaliDir(os.path.join(
                self.apk_out, item), include=pkgs)

    @staticmethod
    def find_pkg_refx_manifest(manifest):
        '''
        找出与清单相关的包
        '''
        if not manifest:
            return
        pkgs = set()
        ptn_s = r'android:name="([^\.]*?\.[^\.]*?)\..*?"'
        ptn = re.compile(ptn_s)

        for item in ptn.finditer(manifest):
            pkgs.add(item.groups()[0])

        if "android.intent" in pkgs:
            pkgs.remove("android.intent")
        if "android.permission" in pkgs:
            pkgs.remove("android.permission")

        return pkgs

    init_smali_argparser = argparse.ArgumentParser()
    init_smali_argparser.add_argument(
        '-m', '--manifest', action='store_true', help='根据manifest相关包初始化')
    init_smali_argparser.add_argument(
        '-f', '--filter', action='store_true', help='根据过滤列表初始化')

    @with_argparser(init_smali_argparser)
    def do_init_smali(self, args):
        '''
        初始化smali，默认初始化所有

        '''
        pkgs = None

        if args.manifest:
            pkgs = self.find_pkg_refx_manifest(self.apk.get_org_manifest())

        self.smali_dir = None
        for item in os.listdir(self.apk_out):
            if not item.startswith('smali'):
                continue

            sd = SmaliDir(os.path.join(self.apk_out, item), include=pkgs)
            if self.smali_dir:
                self.smali_dir[len(self.smali_dir):] = sd
            else:
                self.smali_dir = sd
                # print('初始化{0}个smali文件'.format(len(self.smali_dir)))

        for items in self.smali_dir:
            for mtd in items.get_methods():
                self.file_list.append(mtd.get_desc())

        print('初始化{0}个smali文件'.format(len(self.smali_dir)))

    def do_build(self, arg):
        '''
        使用apktool回编译apk
        '''
        apktool.build(self.apk_out, force=True)

    def __init__smali_dir(self):
        pass

    def show_risk_perm(self):
        result = ''
        if not self.apk.get_manifest():
            return result

        risk_perms = [
            '_SMS',
            '_CALL',
            '_DEVICE_ADMIN',
            '_AUDIO',
            '_CONTACTS'
        ]
        ps = set()
        pflag = True

        def process_perm_item(item, pflagx=pflag):

            for perm in risk_perms:
                if perm not in item.get('@android:name'):
                    continue

                if pflagx:
                    result += Color.red('===== Risk Permissions =====\n')
                    pflagx = False

                name = item.get('@android:name')
                if name in ps:
                    continue
                result += name + '\n'
                ps.add(name)

        perms = self.apk.get_manifest().get('uses-permission', [])

        if isinstance(perms, dict):
            process_perm_item(perms)
        else:
            for item in self.apk.get_manifest().get('uses-permission', []):
                process_perm_item(item)

        app = self.apk.get_manifest().get('application')
        if app is None:
            return result

        recs = app.get('receiver', None)

        def process_item(item):
            text = ''
            perm = item.get('@android:permission', '')
            if '_DEVICE' not in perm:
                return text
            if pflag:
                text += Color.red('===== Risk Permissions =====\n')
            text += perm + item.get('@android:name') + '\n'

        if isinstance(recs, dict):
            text = process_item(item)
            if text:
                result += text
                pflag = False
        elif isinstance(recs, list):
            for item in recs:
                text = process_item(item)
                if text:
                    result += text
                    pflag = False
                    break

        if not pflag:
            result += '\n'

        return result

    def show_risk_code(self, level):
        result = Color.red('===== Risk Codes =====\n')
        for k, v in RISKS.items():
            if v['lvl'] < level:
                continue
            kflag = True
            for sf in self.smali_dir:
                for mtd in sf.get_methods():
                    mflag = True
                    lines = re.split(r'\n\s*', mtd.get_body())
                    for idx, line in enumerate(lines):
                        for ptn in v['code']:
                            if re.search(ptn, line):
                                if kflag:
                                    result += Color.magenta('---' +
                                                            k + '---\n')
                                    kflag = False
                                if mflag:
                                    result += Color.green(' ' +
                                                          str(mtd)) + '\n'
                                    mflag = False
                                result += ' ' * 3 + str(idx) + line + '\n'
                                break

        return result

    risk_parser = argparse.ArgumentParser()
    risk_parser.add_argument(
        '-l', '--level', help='指定风险级别，0/1/2/3，0为最低级别，3为最高级别')
    risk_parser.add_argument(
        '-f', '--force', action='store_true', help='强制覆盖已有文件')

    @with_argparser(risk_parser)
    def do_risk(self, args):
        if os.path.exists(self.apk_path + '.risk.txt'):
            if not args.force:
                # TODO read file
                return
        text = ''
        text += self.show_risk_perm()

        level = 3
        if args.level:
            level = int(args.level)

        text += self.show_risk_code(level)
        text += self.show_risk_children()
        # TODO save to file
        self.ppaged(text)
        # so
        # 文本
        # 二进制文件
        # 图片

    def ref(self, desc):
        global notes
        global classes
        global recursion_times
        recursion_times += 1

        if recursion_times > recursion_limit:
            return

        body = None
        for smali_file in self.smali_dir:
            for mtd in smali_file.get_methods():
                if desc in str(mtd):
                    body = mtd.get_body()
                    break
        print(desc)

        if body:
            for smali_file in self.smali_dir:
                for mtd in smali_file.get_methods():
                    if desc in mtd.get_body():
                        if desc.startswith('L'):
                            tmp = desc[: desc.index(';')]
                            classes.add(tmp[: tmp.rindex('/')])
                        tmp = str(mtd)[: str(mtd).index(';')]
                        classes.add(tmp[: tmp.rindex('/')])
                        notes.append([desc, str(mtd)])
                        self.ref(str(mtd))

    def refs(self, desc):
        self.ref(desc)

    def do_xrefs(self, arg):
        pass

    ref_parser = argparse.ArgumentParser()
    ref_parser.add_argument('-l', '--limit', help='递归次数')

    @with_argparser(ref_parser)
    def do_ref(self, args):
        if len(args) != 1:
            return

        if args.limit:
            recursion_limit = args.l

        mtd = args[0]
        self.refs(mtd)

        dot = Digraph()
        if notes:
            dot.edges(notes)
            dot.render('refs.gv', view=True)

    def main_ref(self, arg):
        '''
            生成入口函数调用数，调用层数默认100。
            可以传入一个数值修改递归次数。
        '''
        args = arg.split()
        if len(args) == 1:
            times = int(args[0])
            global recursion_limit
            recursion_limit = times
        else:
            recursion_limit = 100

        dot = Digraph()
        dot.attr('node', style='filled', fillcolor='red')

        # global recursion_times
        # recursion_times = 0
        # if not self.smali_files:
        #     self.smali_files = parse_smali(self.apk_out + os.sep + 'smali')

        main_acitivity = self.get_main_activity()
        main_acitivity = main_acitivity.replace(
            '.', '/') + ';->onCreate'
        self.refs(main_acitivity)
        dot.node(main_acitivity)

        # recs = self.apk.get_receivers()
        # for item in recs:
        #     dot.node(item)
        #     self.refs(item)

        # dot.attr('node', shape='box', style='filled',
        #          fillcolor='white', color='black')

        # if notes:
        #     dot.edges(notes)
        #     dot.render('refs.gv', view=True)

        # for item in sorted(list(classes)):
        #     print(item)

    search_parser = argparse.ArgumentParser()
    search_parser.add_argument('txt', help='默认在Dex中搜索字符串')
    # <public type="string" name="failed_text" id="0x7f050002" />
    search_parser.add_argument(
        '-r', '--res', action='store_true', help='查找资源（id/name/图片名）')
    search_parser.add_argument(
        '-a', '--all', action='store_true', help='在所有文本文件中查找（不包含Dex）')

    @with_argparser(search_parser)
    def do_search(self, args):
        def find_in_the_layout_xml(txt):
            results = []
            layout_path = os.path.join(self.apk_out, 'res', 'layout')
            for root, _, names in os.walk(layout_path):
                for name in names:
                    xml_path = os.path.join(root, name)
                    with open(xml_path, mode='r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if txt in line:
                                results.append(os.path.splitext(name)[0])
                                break
            return results

        def find_in_the_smali_dir(txt):
            for smali_file in self.smali_dir:
                if txt in smali_file.get_content():
                    print(smali_file)

        def find_in_the_txt(content):
            self.apk.get_files().sort(key=lambda k: (k.get('type'), k.get('name')))
            for item in self.apk.get_files():
                if item.get('type') != 'txt':
                    continue
                if 'META-INF' in item.get('name'):
                    continue
                txt_path = os.path.join(self.apk_out, item.get('name'))
                with open(txt_path, mode='r') as f:
                    if 'txt_path' in f.read():
                        print(item.get('name'))

        if args.res:
            public_xml = os.path.join(
                self.apk_out, 'res', 'values', 'public.xml')
            rtype = None
            rname = None
            with open(public_xml, mode='r') as f:
                lines = f.readlines()
                flag = False
                for line in lines:
                    if args.txt in line:
                        match = line.strip()
                        print(match)
                        g = re.search(
                            r'type="(.*?)" name="(.*?)"', match).groups()
                        if g:
                            rtype = g[0]
                            rname = g[1]
                        break
                else:
                    return

            if rtype in {'string', 'layout'}:
                find_in_the_smali_dir(rname)
            elif rtype in {'id', 'drawable'}:
                txts = find_in_the_layout_xml(rname)
                for txt in txts:
                    print(os.path.join('res', 'layout', txt + '.xml'))
                    find_in_the_smali_dir(txt)
                    print()
        elif args.all:
            find_in_the_txt(args.txt)
        else:
            find_in_the_smali_dir(args.txt)

    vjava_parser = argparse_completer.ACArgumentParser(prog='vjava')

    def do_dex2java(self, args):
        """将APK转化为Java代码，使用vjava可以查看。
        """
        from .decompiler.enjarify import dex2jar
        output = os.path.join(self.apk_out, 'classes.jar')
        dex2jar(self.apk_path, output=output)
       
        from .decompiler.cfr import class2java
        java_output = os.path.join(self.apk_out, 'java')
        print(java_output)
        class2java(output, java_output)

    def do_init_java(self, args):
        java_output = os.path.join(self.apk_out, 'java')
        for root, dirs, files in os.walk(java_output):
            for d in dirs:
                for f in files:
                    self.java_files.append(os.path.join(root, d, f))

    vjava_parser = argparse_completer.ACArgumentParser(prog='vjava')

    @cmd2.with_argparser(vjava_parser)
    def do_vjava(self, args):
        """查看java代码，可以指定类、方法

        Args:
            args (TYPE): 类、方法
        """
        # TODO 封装cfr
        # TODO 修改apktutils的反编译接口
        if not self.java_files:
            print('please dex2jar and init java')
            return

        try:
            with open(args.jfile) as f:
                print(f.read())
        except Exception as e:
            pass

    vsmali_parser = argparse_completer.ACArgumentParser(prog='vsmali')

    # @cmd2.with_category('CAT_AUTOCOMPLETE')
    @cmd2.with_argparser(vsmali_parser)
    def do_vsmali(self, args):
        """查看smali代码，可以指定类、方法
        Args:
            args (TYPE): 类、方法（自动生成）
        """
        # TODO 判断smali目录是否为空
        # 如果为空，直接提示，请反编译
        if not self.smali_dir:
            print('please decompile and init smali')
            return

        try:
            print(self.smali_dir.get_method_from_desc(args.sfile).get_body())
        except Exception as e:
            pass

        # for item in self.smali_dir:
        #     print(dir(item))
        #     print(item.get_file_path(), item.get_class(), item.get_methods())
        # for item in self.smali_files:
            # print(item)
        #

    # ------------------- ADB -------------------------
    adb_parser = argparse.ArgumentParser()
    adb_parser.add_argument(
        '-s', '--serial', help='use device with given serial (overrides $ANDROID_SERIAL)')

    @with_argparser(adb_parser)
    def do_adb_ready(self, args):
        '''
        连接设备/模拟器，准备adb命令。
        '''
        serial = None
        if args.serial:
            serial = args.serial

        self.adb = pyadb3.ADB(device=serial)
        if len(self.adb.get_output().decode()) > 10:
            print('ADB ready.')
        else:
            print("unable to connect to device.")

    def do_adb(self, arg):
        '''
        执行adb命令
        '''
        if not self.adb:
            self.adb = pyadb3.ADB()
        self.adb.run_cmd(arg)
        print(self.adb.get_output().decode('utf-8', errors='ignore'))

    def do_adb_shell(self, arg):
        '''
        执行adb shell命令
        '''
        if not self.adb:
            self.adb = pyadb3.ADB()

        self.adb.run_shell_cmd(arg)
        print(self.adb.get_output().decode('utf-8', errors='ignore'))

    def do_topactivity(self, args):
        if not self.adb:
            self.adb = pyadb3.ADB()

        self.adb.run_shell_cmd(
            "dumpsys activity activities | grep mFocusedActivity")
        print(self.adb.get_output().decode(
            'utf-8', errors='ignore').split()[-2])

    def do_details(self, args):
        if not self.adb:
            self.adb = pyadb3.ADB()
        self.adb.run_shell_cmd("dumpsys package {}".format(self.get_package()))
        print(self.adb.get_output().decode('utf-8', errors='ignore'))

    # ------------------- 备份还原 -------------------------

    # ------------------- 应用管理 -------------------------
    lspkgs_parser = argparse.ArgumentParser()
    lspkgs_parser.add_argument(
        '-f', '--file', action='store_true', help='显示应用关联的 apk 文件')
    lspkgs_parser.add_argument(
        '-d', '--disabled', action='store_true', help='只显示 disabled 的应用')
    lspkgs_parser.add_argument('-e', '--enabled', action='store_true',
                               help='只显示 enabled 的应用')
    lspkgs_parser.add_argument(
        '-s', '--system', action='store_true', help='只显示系统应用')
    lspkgs_parser.add_argument(
        '-3', '--three', action='store_true', help='只显示第三方应用')
    lspkgs_parser.add_argument(
        '-i', '--installer', action='store_true', help='显示应用的 installer')
    lspkgs_parser.add_argument(
        '-u', '--uninstall', action='store_true', help='包含已卸载应用')
    lspkgs_parser.add_argument(
        'filter', type=str, nargs="?", help='包名包含 < FILTER > 字符串')

    @with_argparser(lspkgs_parser)
    def do_lspkgs(self, args):
        '''
        查看应用列表，默认所有应用
        '''
        cmd = 'pm list packages'
        if args.file:
            cmd += ' -f'

        if args.disabled:
            cmd += ' -d'
        elif args.enabled:
            cmd += ' -e'

        if args.system:
            cmd += ' -s'
        elif args.three:
            cmd += ' -3'

        if args.installer:
            cmd += ' -i'
        elif args.uninstall:
            cmd += ' -u'

        if args.filter:
            cmd += ' ' + args.filter

        self.adb.run_shell_cmd(cmd)
        print(self.adb.get_output().decode())

    def do_install(self, arg):
        '''
        安装应用到手机或模拟器
        '''
        self.adb.run_cmd('install -r -f {}'.format(self.apk_path))
        output = self.adb.get_output().decode()

        if self.adb.get_error():
            print(self.adb.get_error().decode(errors='ignore'))
        elif 'Failure' in output:
            print(output)
        else:
            # TODO if the sdcard path doesn't exist.
            cmd = 'touch %s.now' % self.sdcard
            self.adb.run_shell_cmd(cmd)

    def do_uninstall(self, arg):
        '''
        卸载应用
        '''
        self.adb.run_cmd('uninstall %s' % self.get_package())
        self.clearsd()

    def clearsd(self):
        ''' pull the newer files from sdcard.
        '''
        cmd = 'find %s -path "%slost+found" -prune -o -type d -print -newer %s.now -delete' % (
            self.sdcard, self.sdcard, self.sdcard)
        self.adb.run_shell_cmd(cmd)

    startapp_parser = argparse.ArgumentParser()
    startapp_parser.add_argument('-d', '--debug', action='store_true')

    def do_strace(self, args):
        '''
        使用 strace 跟踪应用
        setenforce 0  # In Android 4.3 and later, if SELinux is enabled, strace will fail with "strace: wait: Permission denied"

        有两种方式：
        1. 使用调试的方式启动应用，strace -p $pid
        2. trace -p $zygote_pid，启动应用
        '''
        # cmd = "strace -f -p `ps | grep zygote | awk '{print $2}'`"
        print(self.sdcard)
        cmd = "set `ps | grep zygote`; strace -p $2 -f -tt -T -s 500 -o {}strace.txt".format(
            self.sdcard)
        self.adb.run_shell_cmd(cmd)

    @with_argparser(startapp_parser)
    def do_startapp(self, args):
        '''启动应用'''
        main_acitivity = self.get_main_activity()
        if not main_acitivity:
            print("It does not have main activity.")
            return

        cmd = 'am start -n %s/%s' % (self.get_package(), main_acitivity)
        if args.debug:
            cmd = 'am start -D -n %s/%s' % (self.get_package(), main_acitivity)

        self.adb.run_shell_cmd(cmd)

    def do_stopapp(self, arg):
        '''停止应用'''
        cmd = 'am force-stop %s' % self.get_package()
        self.adb.run_shell_cmd(cmd)

    kill_parser = argparse.ArgumentParser()
    kill_parser.add_argument('-a', '--all', action='store_true')

    @with_argparser(kill_parser)
    def do_kill(self, args):
        '''杀死应用'''
        cmd = 'am kill %s' % self.get_package()
        if args.all:
            cmd = 'am kill-all'

        self.adb.run_shell_cmd(cmd)

    def do_clear(self, args):
        cmd = 'pm clear {}'.format(self.get_package())
        self.adb.run_shell_cmd(cmd)

    def do_screencap(self, args):
        import time
        cmd = 'screencap -p /sdcard/{}.png'.format(time.time())
        if not self.adb:
            self.adb = pyadb3.ADB()

        self.adb.run_shell_cmd(cmd)

    monkey_parser = argparse.ArgumentParser()
    monkey_parser.add_argument('-v', '--verbose', action='store_true')
    monkey_parser.add_argument('count', type=int, help="Count")

    @with_argparser(monkey_parser)
    def do_monkey(self, args):
        if not self.adb:
            self.adb = pyadb3.ADB()

        cmd = "monkey -p {} ".format(self.get_package())
        if args.verbose:
            cmd += '-v '

        cmd += str(args.count)

        self.adb.run_shell_cmd(cmd)
        print(self.adb.get_output().decode())
    # --------------------------------------------------------

    def do_set_sdcard(self, arg):
        '''
        设置sdcard位置
        '''
        if len(arg.split()) != 1:
            print('Please give one argument to set sdcard path.')
            return
        self.sdcard = arg

    # @options([make_option('-d', '--debug', action='store_true'),
    #           make_option('-e', '--edit', action='store_true')])
    def do_test(self, args):
        '''
        测试应用（未支持）
        '''
        print(args)
        print(''.join(args))
        if args.debug:
            print('debug')

        # TODO 增加自动化测试
        # 获取Receiver， 启动
        # 获取Service，启动
        # 获取Acitivity，启动

    def do_pids(self, arg):
        '''
        显示应用进程
        '''
        print(self.adb.run_shell_cmd('ps | grep %s' % self.get_package()))

    def lsof(self):
        axml = self.apk.get_manifest()
        if axml:
            lines = self.adb.run_shell_cmd('ps | grep %s' %
                                           axml.getPackageName()).decode()
            if not lines:
                return
            pids = []
            for line in lines.strip().split('\r\r\n'):
                pids.append(line.split()[1])

            for pid in pids:
                self.adb.run_shell_cmd('lsof | grep %s' % pid)
                lines = self.adb.get_output().decode().split('\r\r\n').decode()
                for line in lines:
                    # print(line)
                    if not line.endswith('(deleted)'):
                        continue

                    tmps = line.split()
                    fdno = tmps[3]
                    if not fdno.isdecimal():
                        continue

                    print(line)
                    filename = tmps[8].replace('/', '_')
                    print('%s %s' % (fdno, filename))
                    self.adb.run_shell_cmd(
                        "cat /proc/%s/fd/%s > /storage/sdcard0/%s" % (pid, fdno, filename))
                    self.adb.run_cmd(
                        'pull -a -p /storage/sdcard0/%s' % filename)

    def do_lssd(self, arg):
        '''列出SDCARD新增的文件'''
        command = ('find /storage/sdcard0 -path "/storage/sdcard0/lost+found"'
                   ' -prune -o -type f -print -newer /storage/sdcard0/.now')
        self.adb.run_shell_cmd(command)
        print(self.adb.get_output().decode())

    def pulldata(self):
        '''
            pull /data/data/pkg
        '''
        pkg = self.get_package()
        self.adb.run_shell_cmd('cp -r /data/data/%s /storage/sdcard0' % pkg)
        # self.adb.run_cmd('pull -a -p /storage/sdcard0/%s %s' % (pkg, pkg))
        # self.adb.run_shell_cmd('rm -r /storage/sdcard0/%s' % pkg)

    def pullsd(self):
        '''
            pull the newer files from sdcard.
        '''
        command = (
            'find /storage/sdcard0 -path "/storage/sdcard0/lost+found"'
            ' -prune -o -type f -print -newer /storage/sdcard0/.now'
        )
        ret = self.adb.run_shell_cmd(command).decode()

        dir_set = set([])
        import os
        for line in ret.split('\r\r\n'):
            if line == '/storage/sdcard0/.now':
                continue
            if line:
                print('->', line)
                path = os.path.dirname(line)
                flag = 0
                skip_path = None
                for item in dir_set:
                    if item == path:
                        flag == 2
                        break

                    if item in path:
                        flag = 2
                        break

                    if path in item:
                        flag = 1
                        skip_path = item
                        break

                if flag == 1:
                    print(path, skip_path)
                    dir_set.add(path)
                    dir_set.remove(skip_path)

                elif flag == 0:
                    dir_set.add(path)

        for line in dir_set:
            print(line, )
            local_path = os.path.dirname(line)[1:]
            if not os.path.exists(local_path):
                os.makedirs(local_path)
            self.adb.run_cmd('pull -a %s %s' % (line, local_path))

    def do_pull(self, arg):
        '''导出样本的所有的运行生成的文件'''
        self.pulldata()
        self.pullsd()

    # ----------------------------- 内存操作 -----------------------------
    # 内存字符串查看？内存字符串修改？
    def do_memview(self, arg):
        '''查看内存分布'''
        if not self.maps:
            self.get_maps()

        print(self.maps)

    def get_maps(self):
        pkg = self.get_package()
        lines = self.adb.run_shell_cmd('ps | grep %s' % pkg).decode()
        pids = []
        for line in lines.strip().split('\r\r\n'):
            pids.append(line.split()[1])

        for pid in pids:
            lines = self.adb.run_shell_cmd('ls /proc/%s/task/' % pid)
            clone = lines.decode().split()[-1]
            cmd = 'cat /proc/%s/maps' % clone
            self.adb.run_shell_cmd(cmd).decode()
            self.maps = self.adb.get_output().decode()

    def memdump(self, arg):
        '''
        内存Dump（仍未支持，需要gdb）

        用法：
        memdump 内存起始地址 内存结束地址
        '''
        pass
        # args = arg.split()
        # if len(args) != 2:
        #     print('Please give the start_addr and end_addr')
        #     return
        # start_addr = args[0]
        # end_addr = args[1]

        # pid = 1
        # outpath = '/data/local/tmp/dump'
        # command = (
        #     "/data/local/tmp/gdb "
        #     "--batch --pid $CLONE "
        #     "-ex 'dump memory /data/local/tmp/dump.dex "
        #     "$DEX_START 0x$MEMORY_END'")

        # self.adb.run_shell_cmd(command)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='analyse', description='analyse apk')
    parser.add_argument('f', help='apk/dex/axml')
    args = parser.parse_args()

    sys.argv.remove(args.f)

    CmdLineApp(args.f).cmdloop()

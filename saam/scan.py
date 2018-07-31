
import argparse
import fnmatch
import os
import tempfile
import zipfile
from codecs import open

import pypandoc
from cigam import Magic
from colorclass.color import Color

import yara

from saam import YARA_PATH, YARAC_PATH


def compile_yara_rules():
    yara_files = {}
    for root, _, filenames in os.walk(YARA_PATH):
        for filename in fnmatch.filter(filenames, '*.yara'):
            path = os.path.join(root, filename)
            yara_files[path] = path

    rules = yara.compile(filepaths=yara_files)
    rules.save(YARAC_PATH)

def get_rules():
    return yara.load(YARAC_PATH)


def build_match_dict(matches):
    results = {}
    for match in matches:
        tags = ', '.join(sorted(match.tags))
        value = match.meta.get('description', match)
        if tags in results:
            if value not in results[tags]:
                results[tags].append(value)
        else:
            results[tags] = [value]
    return results


def scan_apk(apk_path, rules, timeout):
    td = None
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                td = tempfile.mkdtemp()
                zf.extract(name, td)

                file_path = os.path.join(td, name)
                key_path = '{}!{}'.format(apk_path, name)
                match_dict = do_yara(file_path, rules, timeout)
                if len(match_dict) > 0:
                    print_matches(key_path, match_dict)

    except Exception as e:
        print(e)
    
    from apkutils import APK
    txt = APK(apk_path).get_org_manifest()
    match_dict = scan_manifest(txt, rules, timeout)
    if len(match_dict) > 0:
        key_path = '{}!{}'.format(apk_path, 'AndroidManifest.xml')
        print_matches(key_path, match_dict)

def scan_manifest(txt, rules, timeout):
    matches = rules.match(data=txt, timeout=timeout)
    return build_match_dict(matches)



def do_yara(file_path, rules, timeout):
    matches = rules.match(file_path, timeout=timeout)
    return build_match_dict(matches)

def print_matches(key_path, match_dict):
    ''' example matches dict
    [{
      'tags': ['foo', 'bar'],
      'matches': True,
      'namespace': 'default',
      'rule': 'my_rule',
      'meta': {},
      'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
    }]
    '''
    print(Color.green("[*] {}".format(key_path)))
    for tags in sorted(match_dict):
        values = ', '.join(sorted(match_dict[tags]))
        print(" |-> {} : {}".format(tags, values))

def scan(file_path, rules, timeout):
    file_type = Magic(file_path).get_type()
    try:
        if 'apk' == file_type:
            scan_apk(file_path, rules, timeout)
        else:
            match_dict = do_yara(file_path, rules, timeout)
            if len(match_dict) > 0:
                print_matches(file_path, match_dict)

    except yara.Error as e:
        print(e)


def main(args):

    if args.c or not os.path.exists(YARAC_PATH):
        compile_yara_rules()

    if not os.path.exists(args.input):
        return

    rules = get_rules()

    if os.path.isdir(args.input):
        for root, _, filenames in os.walk(args.input):
            for filename in filenames:
                scan(os.path.join(root, filename), rules, args.timeout)
    else:
        scan(args.input, rules, args.timeout)

# TODO 对于清单的匹配，直接使用apkutils取出来匹配即可
# 如果是这样，那么dex直接拿自付出出来，直接匹配？

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='idad', description='')
    parser.add_argument('input', help="apk path")
    parser.add_argument('-c', action='store_true', help="编译yara")
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help="Yara scan timeout (in seconds)")
    args = parser.parse_args()
    main(args)

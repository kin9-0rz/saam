
import argparse
import os
import random
import string
from subprocess import PIPE, Popen

import pexpect
from pexpect.popen_spawn import PopenSpawn


def random_str(len=random.randint(1, 6)):

    chars = string.ascii_letters + string.digits
    return ''.join([random.choice(chars) for i in range(len)])

PWD = random_str(10)


def genarate_key(key_name='debug.keystore', alias='release'):
    """使用keytool生成随机证书

    Returns:
        type: 无

    """
    cmd = ('keytool -genkeypair -keystore {} '
           '-alias {} -validity 3000').format(key_name, alias)
    child = PopenSpawn(cmd)

    result = child.expect('Enter keystore password:')
    # print('Enter keystore password:')
    child.sendline(PWD)

    child.expect(r'Re-enter new password:')
    # print('Re-enter new password:')
    child.sendline(PWD)

    child.expect(']:')
    # print('What is your first and last name?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    # print('What is the name of your organizational unit?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    # print('What is the name of your organization?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    # print('What is the name of your City or Locality?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    # print('What is the name of your State or Province?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    # print('What is the two-letter country code for this unit?\r\n  [Unknown]:')
    child.sendline(random_str())

    child.expect(']:')
    print(child.before[5:-15].decode(), end=' ')
    child.sendline('yes')

    child.expect('Enter key password for')
    # print('Enter key password for <release>\r\n\t(RETURN if same as keystore password):')
    child.sendline(PWD)

    child.expect('password:')
    # print('Re - enter new password:')
    child.sendline(PWD)
    child.wait()

    # print(PWD)

    return (key_name, alias)


def jarsigner(jar_path, key_path, alias):
    """使用jarsigner签名

    Args:
        flag (bool): 是否兼容Android 4.2以下

    Returns:
        type: None

    """
    # 不支持Android 4.2 以下
    cmd = 'jarsigner -keystore {} {} {}'.format(key_path, jar_path, alias)
    child = PopenSpawn(cmd)
    result = child.expect('Enter Passphrase for keystore:')
    child.sendline(PWD)
    child.wait()
    os.remove(key_path)


def apksigner(jar_path, key_path, alias):
    """使用apksigner签名

    Returns:
        type: None
    """
    cmd = ('apksigner sign --ks {} '
           '--ks-key-alias {} {}').format(key_path, alias, jar_path)
    child = PopenSpawn(cmd)
    result = child.expect('Keystore password for signer #1:')
    child.sendline(PWD)
    child.wait()
    os.remove(key_path)


def main(args):
    """证书生成和签名

    对一个或多个APK使用随机证书签名，证书使用后会自动删除。
    """
    def sign(file_path, ver):
        print(file_path, flush=True, end=' ')
        key_name, alias = genarate_key()
        if ver == 'v1':
            jarsigner(file_path, key_name, alias)
        else:
            apksigner(file_path, key_name, alias)
        print('OK')

    if not os.path.exists(args.input):
        print('The file {} is not found！'.format(args.input))
        return

    if os.path.isfile(args.input):
        sign(args.input, args.version)
        return

    for parent, _, filenames in os.walk(args.input):
        for filename in filenames:
            file_path = os.path.join(parent, filename)
            sign(file_path, args.version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='sign', description='自动签名')
    parser.add_argument('version', choices=['v1', 'v2'], help="指定签名版本")
    parser.add_argument('input', help="apk path")

    args = parser.parse_args()
    main(args)

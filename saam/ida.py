# fork from : https://github.com/wanchouchou/AndroidNativeDebug
# Modified 2to3, more intelligence.

import argparse
import sys
from sys import stdin, exit
import os
import subprocess

from pyadb3 import ADB


class Apk_manager(object):

    def __init__(self, adb, adb_path, apk_path, aapt_path):
        self.value = ''
        self.pos = 0
        self.adb_path = adb_path
        self.apk_path = apk_path
        self.aapt_path = aapt_path
        self.data = ''
        self.adb = adb

    def is_apk_exist(self):
        if os.path.exists(self.apk_path):
            return True
        else:
            print('[E] Find apk failed!')
            return False

    def init_apk_info(self, aapt_path):
        if self.is_apk_exist() is False:
            self.data = ''
            return ''
        if aapt_path is None:
            print('[E] Must set the path of aapt in Config.py!')
            self.data = ''
            return ''
        get_info_cmd = self.aapt_path + ' d badging ' + self.apk_path
        try:
            self.data = os.popen(get_info_cmd).read()
        except Exception as e:
            print(('[E] Exec cmd: %s failed!' % get_info_cmd))
            print(e)
            self.data = ''

        return ''

    def get_content(self, mark):
        data = self.data
        markIndex = data[self.pos:].index(mark)
        firstSinglequotesIndex = markIndex + len(mark) + self.pos
        lastSinglequotesIndex = data[
            firstSinglequotesIndex + 1:].index('\'') + firstSinglequotesIndex + 1
        self.value = data[firstSinglequotesIndex + 1: lastSinglequotesIndex]
        self.pos = lastSinglequotesIndex

    def get_packagename(self):
        if self.data == '':
            return ''
        package_mark = 'package: name='
        self.get_content(package_mark)
        print(('[+] PackageName is \'', self.value, '\''))
        return self.value

    def get_mainactivity(self):
        if self.data == '':
            return ''

        mainactivity_mark = 'launchable-activity: name='
        self.get_content(mainactivity_mark)
        print(('[+] MainActivity is \'', self.value, '\''))
        return self.value

    def __build_command__(self, cmd):
        ret = self.adb_path + ' ' + cmd
        if sys.platform.startswith('win'):
            return ret
        else:
            ret = ret.split()

        return ret

    def install_apk(self):
        print(('[+] Install apk: %s' % os.path.basename(self.apk_path)))
        if self.is_apk_exist() is False:
            print(('[E] The apk: %s is not exists!' % self.apk_path))
            exit(-3)
        # Do not use adb.run_cmd when installing the apk, please
        # look at the Abdroid_native_debug.exec_android_server() for
        # details reason
        cmd = self.__build_command__(' install -f ' + self.apk_path)
        adb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # if i use read() instead of readline, this function maybe block. I don't
        # know why~
        ret_line = adb_process.stdout.readline().decode()
        print(('[+] ' + ret_line.strip('\n')))
        print('[W]\tInstalling......\n\tNow you maybe need to wait several seconds, please be patient......')
        ret_line = adb_process.stdout.readline().decode()
        print(('[+]\t' + ret_line.strip('\n')))

    def launch_apk(self):
        self.init_apk_info(self.aapt_path)
        package_name = self.get_packagename()
        mainactivity_name = self.get_mainactivity()
        if package_name == '' or mainactivity_name == '':
            print('[ERROR] get package/MainActivity name failed!')
            return
        startAppCMD = 'am start -D -n ' + \
            package_name + '/' + mainactivity_name
        self.adb.run_shell_cmd(startAppCMD)

        # wait for user attaching the target process in IDA
        print(('[W]=== Now please attach process \'%s\' in IDA' % package_name))


class Android_native_debug(object):

    def __init__(self, apk_path, adb_path, aapt_path, is_emulator=False):
        self.apk_path = apk_path
        self.adb_path = adb_path
        self.aapt_path = aapt_path

        self.adb_wrapper = ADB(adb_path)
        
        self.apk_manager = Apk_manager(
            self.adb_wrapper, self.adb_path, self.apk_path, self.aapt_path)

        # self.is_emulator = True if is_emulator else self.is_target_emulator()
        self.adb_server_process = None

    def __build_command__(self, cmd):
        ret = self.adb_path + ' ' + cmd
        if sys.platform.startswith('win'):
            return ret
        else:
            ret = ret.split()

        return ret

    def install_apk(self):
        self.apk_manager.install_apk()

    def is_androidServer_exist(self):
        base_cmd = 'ls -l /data/local/tmp'
        ret = self.adb_wrapper.run_shell_cmd(base_cmd)
        if 'android_server' in ret.decode():
            print('[+] android_server is existed')
            return True

        return False

    def exec_android_server(self):
        if not self.is_androidServer_exist():
            print('android_server is not existed!')
            print('Please push android_server to /data/local/tmp/android_server')
            return

        self.adb_forward()
        print('[+] exec the android_server.')
        print('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        # The self.run_shell_cmd call adb.shell_command function which using subprocess.popen().communicate() to exec shell cmd.
        # But if the target cmd occur a block, such as this case :),
        # then we could not continue running other cmds.
        # To avoid this situation, I use subprocess.popen and manually read the
        # stdout instead of using subprocess.popen(..).communicate()

        shell_cmd = '/data/local/tmp/android_server'
        print('--')
        self.adb_wrapper.__build_command__(shell_cmd)
        # self.adb_wrapper.run_shell_cmd(shell_cmd)
        # print('???')
        # print(self.adb_wrapper.get_output())
        cmd = self.__build_command__(' shell ' + shell_cmd)
        print(cmd)
        adb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # if i use read() instead of readline, this function maybe block.
        # I don't know why~
        ret_line = adb_process.stdout.readline().decode()
        print(('[+] ' + ret_line.strip('\n')))
        print('[W] Now you maybe need to wait several seconds, please be patient......')
        ret_line = adb_process.stdout.readline().decode()
        print(('[+] ' + ret_line.strip('\n')))
        if ret_line.find('bind') > -1:
            print('    (Don\'t be worry, It is also working well )')

    def adb_forward(self):
        print('[+] Begin adb port forwarding......')
        cmd = 'forward tcp:23946 tcp:23946 '
        self.adb_wrapper.run_cmd(cmd)

    def get_pid_by_name(self, process_name):
        pid = ''
        ret = self.adb_wrapper.run_shell_cmd('ps')
        ret_list = ret.split('\n')  # split by '\n'
        for rl in ret_list:
            if rl.find(process_name) > -1:
                elements_list = rl.split(' ')  # split by space
                for i in range(1, len(elements_list), 1):
                    # The frist element must be 'root', so we find the send
                    # element which is not ''
                    if elements_list[i] != '':
                        pid = elements_list[i]
                        print(('[+] the pid of %s is: %s' %
                               (process_name, pid)))
                        break

                if pid != '':
                    break

        return pid

    def kill_android_server(self):
        print('[W] Kill the android_server......')
        if self.adb_server_process is not None:
            self.adb_server_process.terminate()
        # first get the pid of android_server
        pid = self.get_pid_by_name(' /data/local/tmp/android_server')
        if pid != '':
            base_cmd = 'kill -9 %s' % pid
            self.adb_wrapper.run_shell_cmd(base_cmd)

    def exec_apk_in_debugmode(self):
        print('++++++++++++++++++++++++++++++++++++++++++++++++')
        print(('[+] Begin launch \'%s\' in debug mode......' %
               os.path.basename(self.apk_path)))
        self.apk_manager.launch_apk()
        print("[W]=== Have you attached successfully?(N or Enter):")
        cmd = str(stdin.readline())
        if cmd.find('N') > -1 or cmd.find('n') > -1:
            print('[+] Attach failed, Please try again :)')
            # kill android_server
            self.kill_android_server()
            exit(-3)
        else:
            print(
                '[W]=== Now you can open the DDMS and get the jdwp port of target process......')
            print('[W]=== Please input the jdwp port of target process:   ')
            # NOTE: must strip by '\n'! Or the port will be 'xxx\n'
            port = str(stdin.readline()).strip('\n')
            self.connect_process_by_jdb(port)

    def connect_process_by_jdb(self, port):
        jdb_cmd = 'jdb -connect com.sun.jdi.SocketAttach:port=%s,hostname=localhost' % port
        print(('[+] Exec %s' % jdb_cmd))
        os.system(jdb_cmd)


def main(args):
    apk_path = args.apk
    adb_path = 'adb'
    aapt_path = 'aapt'

    android_native_debug = Android_native_debug(
        apk_path, adb_path, aapt_path, args.e)

    android_native_debug.install_apk()
    android_native_debug.exec_android_server()
    android_native_debug.exec_apk_in_debugmode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='idad', description='debug jni with IDA')
    parser.add_argument('apk', help="apk path")
    parser.add_argument('-s', help="set target device")
    parser.add_argument('-e', action='store_true',
                        help="is emulator, if adb shell is #, not $.")

    args = parser.parse_args()
    main(args)

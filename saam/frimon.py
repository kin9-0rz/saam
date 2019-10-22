# 从 Appmon 修改而来的脚本
#
import argparse
import codecs
import os
import sys
import tempfile
import traceback

import frida
from termcolor import colored

VERSION = '0.0.1'

device = ''
session = ''
temp_dir = tempfile.mkdtemp()
merged_script_path = os.path.join(temp_dir, 'merged.js')
APP_LIST = []


def init_opts():
    parser = argparse.ArgumentParser(
        prog='frimon', description='frida=12.2.28, python=3.6.8')
    parser.add_argument('-a', action='store', dest='app_name', default='',
                        help='Process Name, such as "org.lineageos.jelly"')
    parser.add_argument('-p', '--spawn', action='store_true',
                        required=False, help='是否使用Spawn方式启动应用，默认Attach')
    parser.add_argument('-s', action='store', dest='script_path',
                        help='''Path to agent script file;
                    Can be relative/absolute path for a file or directory;
                    Multiple scripts in a directory shall be merged;
                    Needs "-a APP_NAME"''')
    parser.add_argument('-v', action='version',
                        version=VERSION)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    global output_dir, report_name

    results = parser.parse_args()
    app_name = results.app_name
    script_path = results.script_path
    spawn = int(results.spawn)

    if script_path is not None and app_name == '':
        parser.print_help()
        sys.exit(1)

    return app_name, script_path, spawn


def merge_scripts(path):
    global merged_script_path
    script_source = ''
    for root, dirs, files in os.walk(path):
        path = root.split('/')
        for file in files:
            script_path = os.path.join(root, file)
            if script_path.endswith('.js'):
                source = ''
                with codecs.open(script_path, 'r', 'utf-8') as f:
                    source = f.read()
                script_source += '/* ____%s/%s____ */\n\n' % (
                    os.path.basename(root), file) + source + '\n\n'
    with codecs.open(merged_script_path, "w", "utf-8") as f:
        f.write(script_source)
    return merged_script_path


def _exit_():
    print((colored('[INFO] Exiting...', 'green')))
    try:
        os.remove(merged_script_path)
    except Exception as e:
        pass
    sys.exit(0)


def writeBinFile(fname, data):
    with codecs.open(fname, "a", "utf-8") as f:
        f.write(data + '\r\n\r\n')


def list_processes(session):
    print(('PID\tProcesses\n', '===\t========='))
    for app in session.enumerate_processes():
        print(("%s\t%s" % (app.pid, app.name)))


def on_detached():
    print((colored('[WARNING] "%s" has terminated!' % (app_name), 'red')))


ssl_key = {}


def on_message(message, data):
    if message['type'] == 'send':
        result = message['payload']
        if 'client_random' in result:
            ssl_key[result['client_random']] = result['master_key']
            if data:
                import hexdump
                hexdump.hexdump(data)
        else:
            print(result)

    elif message['type'] == 'error':
        print((message['stack']))


def print_ssl_key():
    print()
    print('SSL KEY:')
    for k, v in ssl_key.items():
        print("CLIENT_RANDOM {} {}".format(k, v))


def generate_injection():
    injection_source = ''
    if os.path.isfile(script_path):
        with codecs.open(script_path, 'r', 'utf-8') as f:
            injection_source = f.read()
    elif os.path.isdir(script_path):
        with codecs.open(merge_scripts(script_path), 'r', 'utf-8') as f:
            injection_source = f.read()
    print((colored('[INFO] Building injection...', 'yellow')))
    return injection_source


def getDisplayName(session, app_name):
    try:
        str_script = """/* ____ getPackageName Getter for Android Gadget____ */
'use strict';
rpc.exports = {
  gadgetdisplayname: function () {
    var appName = "";
    Java.perform(function(argument) {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        appName = app.toString().split("@")[0];
    });
    return appName;
}};
"""
        script = session.create_script(str_script)
        script.load()
        if script.exports.gadgetdisplayname:
            app_name = script.exports.gadgetdisplayname()
        script.unload()
        return app_name
    except Exception as e:
        print((colored("[ERROR] " + str(e), "red")))
        traceback.print_exc()


def init_session():
    try:
        session = None
        try:
            # added timeout to wait for 3 seconds
            device = frida.get_usb_device(3)
        except Exception as e:
            print((colored(str(e), "red")))
            traceback.print_exc()
            print((colored("Troubleshooting Help", "blue")))
            print((colored("HINT: Is USB Debugging enabled?", "blue")))
            print(colored(
                "HINT: Is `frida-server` running on mobile device (with +x permissions)?", "blue"))
            print((colored("HINT: Is `adb` daemon running?", "blue")))
            sys.exit(1)
        pid = None
        if app_name:
            try:
                if spawn == 1:
                    print((colored("Now Spawning %s" % app_name, "green")))
                    pid = device.spawn([app_name])
                    # time.sleep(5)
                    session = device.attach(pid)
                    # time.sleep(5)
                else:
                    arg_to_attach = app_name
                    if app_name.isdigit():
                        arg_to_attach = int(app_name)

                    session = device.attach(arg_to_attach)
            except Exception as e:
                print((colored('[ERROR] ' + str(e), 'red')))
                traceback.print_exc()
        if session:
            print((colored('[INFO] Attached to %s' % (app_name), 'yellow')))
            session.on('detached', on_detached)
    except Exception as e:
        print((colored('[ERROR] ' + str(e), 'red')))
        traceback.print_exc()
        sys.exit(1)
    return device, session, pid


try:
    app_name, script_path, spawn = init_opts()
    device, session, pid = init_session()

    if session:
        if app_name == "Gadget":
            app_name = getDisplayName(session, app_name)
        script = session.create_script(generate_injection())
        if script:
            print((colored('[INFO] Instrumentation started...', 'yellow')))
            script.on('message', on_message)
            script.load()
            if spawn == 1 and pid:
                device.resume(pid)
except Exception as e:
    print_ssl_key()
    print((colored('[ERROR] ' + str(e), 'red')))
    traceback.print_exc()
    sys.exit(1)

try:
    while True:
        pass
except KeyboardInterrupt:
    print_ssl_key()
    script.unload()
    session.detach()
    _exit_()

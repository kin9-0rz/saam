import os

import configparser
import yaml

__version__ = '0.0.1'

HOME = os.path.join(os.path.dirname(__file__), '..')

__cfg = configparser.ConfigParser()
__cfg.read(os.path.join(HOME, 'conf.ini'))

# ../tools/apktool/apktool.jar
__APKTOOL_DEFAULT = os.path.join(HOME, 'tools', 'apktool', 'apktool.jar')
__APKTOOL_CONF = __cfg.get('Paths', 'apktool')

APKTOOL_PATH = __APKTOOL_CONF if __APKTOOL_CONF else __APKTOOL_DEFAULT

# __APKTOOL_DEFAULT = os.path.join(HOME, 'tools', 'apktool', 'apktool.jar')
# __APKTOOL_CONF = __cfg.get('Paths', 'smali')

# APKTOOL_PATH = __APKTOOL_CONF if __APKTOOL_CONF else __APKTOOL_DEFAULT

__CFR_DEFAULT = os.path.join(HOME, 'tools', 'cfr.jar')
__CFR_CONF = __cfg.get('Paths', 'cfr')
CFR_PATH = __CFR_CONF if __CFR_CONF else __CFR_DEFAULT

RISKS_PATH = os.path.join(HOME, 'datas', 'risks.yml')
with open(RISKS_PATH, encoding='utf-8') as f:
    RISKS = yaml.load(f.read())

YARA_PATH = os.path.join(HOME, 'rules')
YARAC_PATH = os.path.join(HOME, 'rules', 'rules.yarc')

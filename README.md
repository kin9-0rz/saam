# saam
A set of scripts for analysing android malware(only support **Python3**).

## Install

1. Download and install requirements.
```
git clone https://github.com/mikusjelly/saam.git
cd saam
pip install -r requirements.txt
```

2. yara-python
```
git clone --recursive https://github.com/rednaga/yara-python-1 yara-python
cd yara-python
python setup.py build --enable-dex install
```

3. readline
- Mac `pip install readline
- Win `pip install pyreadline`

4. config

    1. Add `saam/bin` to PATH
    2. config conf.ini

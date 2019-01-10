# SAAM - Scripts for Analysing Android Malware


## 安装
0. Python3 环境。

1. 安装依赖

  ```
  git clone https://github.com/mikusjelly/saam.git
  cd saam
  pip install -r requirements.txt
  ```

2. 安装yara-python

  ```
  git clone --recursive https://github.com/rednaga/yara-python-1 yara-python
  cd yara-python
  python setup.py build --enable-dex install
  ```

3. readline

  - Mac `pip install readline`
  - Win `pip install pyreadline`

4. 配置

    1. Add `saam/bin` to PATH
    2. config conf.ini

## 功能

- apktool，反编译
- analyse，交互式分析
- jadx，阅读代码
- sign，签名
- scan，扫描器
- deobfuscate，反混淆
- ida，自动调试

### deobfuscate，反混淆

```
✗ deobfuscate.sh 34d8aad4474f86d96b97dbbcea6732bb.apk
I: Using Apktool 2.3.1 on 34d8aad4474f86d96b97dbbcea6732bb.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /Users/bin/Library/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
deobfuscate... detmp/smali
classes ... 33
inner classes ... 1
methods ... 253
fields ... 189
java -jar ... ../tools/apktool/apktool.jar b  -f  -o de-34d8aad4474f86d96b97dbbcea6732bb.apk detmp
I: Using Apktool 2.3.1
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
```

| 之前 | 之后 |
| --- | --- |
| ![](https://raw.githubusercontent.com/mikusjelly/saam/master/imgs/de-clz-1.png) | ![](https://raw.githubusercontent.com/mikusjelly/saam/master/imgs/de-clz-2.png) |
| ![](https://raw.githubusercontent.com/mikusjelly/saam/master/imgs/de-mtd-1.png) | ![](https://raw.githubusercontent.com/mikusjelly/saam/master/imgs/de-mtd-2.png) |


## 参考
- [appmon](https://github.com/dpnishant/appmon)
- [ssl_logger](https://github.com/google/ssl_logger)

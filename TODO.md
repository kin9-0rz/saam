https://github.com/tartley/colorama
- [ ] 反编译
- [ ] 风险代码定位 
    - [ ] 风险权限
    - [ ] smali 代码定位敏感字符串
        - [ ] 根据危害类型分类
        - [ ] 欺诈点击
                android.permission.BIND_ACCESSIBILITY_SERVICE performAction(AccessibilityNodeInfo.ACTION_CLICK)
                MotionEvent view.dispatchTouchEvent(motionEvent_2);
    - [ ] 混淆
    - [ ] 模拟器检测
    - [ ] CFG
        - [ ] https://github.com/EugenioDelfa/Smali-CFGs
        - [ ] http://sseblog.ec-spride.de/tools/flowdroid/
        - [ ] https://github.com/dorneanu/smalisca
- [ ] 字符串相似判断 https://github.com/seatgeek/fuzzywuzzy
- [ ] Crack相关
    - [ ] 快速定位资源文件代码未知
- [ ] so 相关分析
- [ ] 动态
    - [ ] 衍生物的保存问题
    - [ ] odex2dex https://github.com/testwhat/SmaliEx
- [ ] Debug
- [ ] frida 脚本
- [ ] ida 脚本
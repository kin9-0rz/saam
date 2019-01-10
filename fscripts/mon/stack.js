'use strict';

function showStack() {
  var stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
  for (var i = 0; i < stack.length; i++) {
    var s = stack[i].toString();
    if (s.indexOf("dalvik.system.") != -1 || s.indexOf("java.lang.") != -1 || s.indexOf("android.widget.") != -1 || s.indexOf("android.os.") != -1 || s.indexOf("android.app.") != -1) {
      continue;
    }
    console.log(stack[i].toString());
  }
}
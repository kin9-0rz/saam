'use strict';
Java.perform(function(argument) {
    console.log("init addView")
//   var Context = Java.use("android.content.Context");
//   var faw = Java.use("android.view.WindowManagerImpl.LayoutParams.FIRST_APPLICATION_WINDOW")
  var wmi = Java.use("android.view.WindowManagerImpl");
  wmi.addView.implementation = function(addView) {
      send(arguments)
    // send(SON.stringify(arguments))
    send(arguments[0])
    send(arguments[1])
    // send(SON.stringify(arguments[1].type))
    // var p = Java.cast()
    showStack()
    return this.addView.apply(this, arguments);
  }
});
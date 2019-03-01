'use strict';

var DEBUG = true;

var SDK = 0;
var SSL_MAX_MASTER_KEY_LENGTH = 48;
var SSL3_RANDOM_SIZE = 32;

///////////////////////////////////////////////////////////////////////////
// helper function
///////////////////////////////////////////////////////////////////////////

// debug log
function logd(s) {
  if (DEBUG) {
    console.log(s);
  }
}

//  info log
function logi(s) {
  console.log(s);
}

// check if undefined
function isUndefined(o) {
  return typeof(o) === "undefined";
}

// Switches the byte order of a 32-bit integer.
//
// @param {number} num Number whose byte order is to be switched
// @returns {number} Number with switched byte order
function ntohl(num) {
  return ((num >>> 8) & 0x0000ff00) | ((num << 8) & 0x00ff0000) |
    ((num >>> 24) & 0x000000ff) | ((num << 24) & 0xff000000);
}

// Switches the byte order of a 16-bit integer.
//
// @param {number} num Number whose byte order is to be switched
// @returns {number} Number with switched byte order
function ntohs(num) {
  return ((num >> 8) & 0x00ff) | ((num << 8) & 0xff00);
}

///////////////////////////////////////////////////////////////////////////
// init
///////////////////////////////////////////////////////////////////////////

// get current Android API Version
try {
  Java.perform(function() {
    var clsBuildVersion = Java.use("android.os.Build$VERSION");
    //logd("[*] SDK_INT=" + JSON.stringify(clsBuildVersion.SDK_INT));
    SDK = (clsBuildVersion.SDK_INT)["value"];
    logi("[*] Android API : " + SDK);
  });
} catch (err) {
  logi("failed to get Android API: err=" + err);
}

var addresses = {};
var SSL_get_fd, SSL_get_rfd, SSL_get_wfd, getsockname, getpeername, SSL_get_session, SSL_SESSION_get_id, i2d_SSL_SESSION, SSL_get_client_random, SSL_SESSION_get_master_key;

// Initializes 'addresses' dictionary and NativeFunctions.
function initialize_globals() {
  logd("initialize_globals");

  var resolver = new ApiResolver("module");

  var additional_lib_name = '';
  if (Process.platform == "darwin") {
    additional_lib_name = "*libsystem*";
  } else {
    additional_lib_name = "*libc*";
  }

  // ntohs & ntohl are exported by libc.so from Android SDK 21
  // additional_lib_functions = ["getpeername", "getsockname", "ntohs", "ntohl"];
  var additional_lib_functions = ["getpeername", "getsockname"];

  var exps = [
    ["*libssl*", ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_rfd", "SSL_get_wfd",
      "SSL_get_session", "SSL_SESSION_get_id", "i2d_SSL_SESSION",
      "SSL_get_client_random", "SSL_SESSION_get_master_key"
    ]],

    [additional_lib_name, additional_lib_functions]
  ];

  for (var i = 0; i < exps.length; i++) {
    var lib = exps[i][0];
    var names = exps[i][1];
    for (var j = 0; j < names.length; j++) {
      var name = names[j];
      var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" + name);
      if (matches.length == 0) {
        logi("[x] Could not find " + lib + "!" + name);
        continue;
      } else if (matches.length != 1) {
        logd("initialize_globals >1 matches=" + matches + " length=" + matches.length);
        // Sometimes Frida returns duplicates.
        var address = 0;
        var s = "";
        var duplicates_only = true;
        for (var k = 0; k < matches.length; k++) {
          if (s.length != 0) {
            s += ", ";
          }
          s += matches[k].name + "@" + matches[k].address;
          logd("initialize_globals >1 s=" + s);
          if (address == 0) {
            address = matches[k].address;
          } else if (!address.equals(matches[k].address)) {
            duplicates_only = false;
          }
        }

        if (!duplicates_only) {
          throw "More than one match found for " + lib + "!" + name + ": " + s;
        }
      }

      addresses[name] = matches[0].address;
    }
  }

  SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
  logd("[*] SSL_get_fd=" + SSL_get_fd);

  SSL_get_rfd = new NativeFunction(addresses["SSL_get_rfd"], "int", ["pointer"]);
  logd("[*] SSL_get_rfd=" + SSL_get_rfd);

  SSL_get_wfd = new NativeFunction(addresses["SSL_get_wfd"], "int", ["pointer"]);
  logd("[*] SSL_get_wfd=" + SSL_get_wfd);

  SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
  logd("[*] SSL_get_session=" + SSL_get_session);

  i2d_SSL_SESSION = new NativeFunction(addresses["i2d_SSL_SESSION"], "int", ["pointer", "pointer"]);
  logd("[*] i2d_SSL_SESSION=" + i2d_SSL_SESSION);

  SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"],
    "pointer", ["pointer", "pointer"]);
  logd("initialize_globals SSL_SESSION_get_id=" + SSL_SESSION_get_id);

  try {
    SSL_get_client_random = new NativeFunction(addresses["SSL_get_client_random"],
      "ulong", ["pointer", "pointer", "ulong"]);
    logd("[*] SSL_get_client_random=" + SSL_get_client_random);

    SSL_SESSION_get_master_key = new NativeFunction(addresses["SSL_SESSION_get_master_key"],
      "ulong", ["pointer", "pointer", "ulong"]);
    logd("[*]  SSL_SESSION_get_master_key=" + SSL_SESSION_get_master_key);
  } catch (err) {
    // logi("[x] " + err); // missing argument
  }

  getpeername = new NativeFunction(addresses["getpeername"], "int", ["int", "pointer", "pointer"]);
  logd("initialize_globals getpeername=" + getpeername);

  getsockname = new NativeFunction(addresses["getsockname"], "int", ["int", "pointer", "pointer"]);
  logd("initialize_globals getsockname=" + getsockname);

  // ntohs & ntohl are exported by libc.so from Android SDK 21
  //ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
  //logd("initialize_globals ntohs=" + ntohs);
  //ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
  //logd("initialize_globals ntohl=" + ntohl);
}

initialize_globals();

///////////////////////////////////////////////////////////////////////////
// main logic
///////////////////////////////////////////////////////////////////////////

//
// Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and "dst_port".
// @param {int} sockfd The file descriptor of the socket to inspect.
// @param {boolean} isRead If true, the context is an SSL_read call. 
//              If false, the context is an SSL_write call.
// @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr", and "dst_port".
function get_address_port_pair(sockfd, isRead) {
  logd("get_address_port_pair sockfd=" + sockfd + " isRead=" + isRead);
  var message = {};
  var addrlen = Memory.alloc(4);
  var addr = Memory.alloc(16);
  var src_dst = ["src", "dst"];

  for (var i = 0; i < src_dst.length; i++) {
    Memory.writeU32(addrlen, 16);
    if ((src_dst[i] == "src") ^ isRead) {
      getsockname(sockfd, addr, addrlen);
    } else {
      getpeername(sockfd, addr, addrlen);
    }

    var _port = ntohs(Memory.readU16(addr.add(2)));
    message[src_dst[i] + "_port"] = _port;
    // TODO could not get the addr
    var _addr = ntohl(Memory.readU32(addr.add(4)));
    message[src_dst[i] + "_addr"] = _addr;
    logd("get_address_port_pair _addr=" + _addr + " _port=" + _port);
  }

  return message;
}

// Get the session_id of SSL object and return it as a hex string.
// @param {!NativePointer} ssl A pointer to an SSL object.
// @return {dict} A string representing the session_id of the SSL object's SSL_SESSION.
//  For example, "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
function get_session_id(ssl) {
  logd("get_session_id ssl=" + ssl);
  var session = SSL_get_session(ssl);
  if (session == 0) {
    return 0;
  }
  var len = Memory.alloc(4);
  var p = SSL_SESSION_get_id(session, len);
  len = Memory.readU32(len);

  var session_id = "";
  for (var i = 0; i < len; i++) {
    // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
    // it to session_id.
    session_id += ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
  }

  logd("get_session_id ret=" + session_id);
  return session_id;
}

// 
function get_master_key(ssl) {
  logd("get_master_key ssl=" + ssl);

  var masterkey = "";
  var p = null;

  var session = SSL_get_session(ssl);
  logd("get_master_key session=" + session);
  if (session == 0) {
    return 0;
  }

  if (SDK >= 26) { // for android 8.0(26 ?)/8.1(27)/9.0(28 ?)
    // size_t SSL_SESSION_get_master_key(const SSL_SESSION *session, unsigned char *out, size_t outlen);
    if (!isUndefined(SSL_SESSION_get_master_key)) {
      p = Memory.alloc(SSL_MAX_MASTER_KEY_LENGTH); // bug? cannot free
      SSL_SESSION_get_master_key(session, p, SSL_MAX_MASTER_KEY_LENGTH);
    }
  } else if (SDK < 26 && SDK > 23) { // for android 7.1(25)/7.0(24)
    p = session.add(12 + 4);
  } else if (SDK == 23) { // for android 6.0(23)
    p = session.add(4 + 4);
  } else if (SDK < 23) { // for android 5.1(22)/5.0(21)/4.4W(20)/4.4(19) ...
    p = session.add(16 + 4);
  } else {
    logi("[X] get_master_key: unexpected result!!!!!!!!!!!!!!!!!");
  }

  if (p != null) {
    for (var i = 0; i < SSL_MAX_MASTER_KEY_LENGTH; i++) {
      // Read a byte, convert it to a hex string (0xAB ==> "AB") and append to masterkey
      masterkey += ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }
  } else {
    logi("[X] get_master_key: Cannot find master key!!!!!!!!!!!!!!!!!");
  }

  logd("get_master_key masterkey=" + masterkey);
  return masterkey;
}

// get client random
function get_client_random(ssl) {
  logd("get_client_random ssl=" + ssl);
  var client_random = "";
  var p = null;

  if (SDK >= 26) { // for android 8.0(26)/8.1(27)/9.0(28)
    // size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen);
    if (!isUndefined(SSL_get_client_random)) {
      p = Memory.alloc(SSL3_RANDOM_SIZE); // bug? cannot free
      SSL_get_client_random(ssl, p, SSL3_RANDOM_SIZE);
    }
  } else if (SDK < 26 && SDK > 23) { // for android 7.1(25)/7.0(24)
    var s3_state_p = ptr(Memory.readU32(ssl.add(56))); // 56=0x38
    logd("SDK=[24,25] s3_state_p=" + s3_state_p);
    p = s3_state_p.add(48); // 48 = 0x30
  } else if (SDK == 23) { // for android 6.0(23)
    var s3_state_p = ptr(Memory.readU32(ssl.add(84))); // 84=0x54
    logd("SDK=23 s3_state_p=" + s3_state_p);
    p = s3_state_p.add(188); // 192 = 0xC0
  } else if (SDK < 23) { // for android 5.1(22)/5.0(21)/4.4W(20)/4.4(19) ...
    var s3_state_p = ptr(Memory.readU32(ssl.add(88))); // 88=0x58
    logd("SDK<23 s3_state_p=" + s3_state_p);
    p = s3_state_p.add(192); // 192 = 0xC0
  } else {
    logi("[X] get_client_random: unexpected result!!!!!!!!!!!!!!!!!");
  }

  logd("get_client_random p=" + p);
  if (p != null) {
    for (var i = 0; i < SSL3_RANDOM_SIZE; i++) {
      client_random += ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }
  } else {
    logi("[X] get_client_random: Cannot find client random!!!!!!!!!!!!!!!!!");
  }

  logd("get_client_random client_random=" + client_random);
  return client_random;
}

///////////////////////////////////////////////////////////////////////////
// hook
///////////////////////////////////////////////////////////////////////////

// int SSL_read(SSL *s, void *buf, int num)
Interceptor.attach(addresses["SSL_read"], {
  onEnter: function(args) {
    logd("[*] SSL_read enter ssl=" + args[0] + " buf=" + args[1] + " num=" + args[2]);

    var message = get_address_port_pair(SSL_get_fd(args[0]), true);
    //var message = get_address_port_pair(SSL_get_rfd(args[0]), true);
    var master_key = get_master_key(args[0]);
    var client_random = get_client_random(args[0]);

    message["ssl_session_id"] = get_session_id(args[0]);
    message["master_key"] = master_key;
    message["client_random"] = client_random;
    message["function"] = "SSL_read";

    this.message = message;
    this.buf = args[1];
  },

  onLeave: function(retval) {
    logd("[*] SSL_read ret retval=" + retval);
    retval |= 0; // Cast retval to 32-bit integer.
    if (retval <= 0) {
      return;
    }

    send(this.message, Memory.readByteArray(this.buf, retval));
  }
});

// int SSL_write(SSL *s, const void *buf, int num)
Interceptor.attach(addresses["SSL_write"], {
  onEnter: function(args) {
    logd("[*] SSL_write enter ssl=" + args[0] + " buf=" + args[1] + " num=" + args[2]);

    var message = get_address_port_pair(SSL_get_fd(args[0]), false);
    //var message = get_address_port_pair(SSL_get_wfd(args[0]), true);
    var master_key = get_master_key(args[0]);
    var client_random = get_client_random(args[0]);

    message["ssl_session_id"] = get_session_id(args[0]);
    message["master_key"] = master_key;
    message["client_random"] = client_random;
    message["function"] = "SSL_write";

    send(message, Memory.readByteArray(args[1], parseInt(args[2])));
  },

  onLeave: function(retval) {
    logd("[*] SSL_write ret retval=" + retval);
  }
});
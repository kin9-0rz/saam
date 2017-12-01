// https://codeshare.frida.re/@lichao890427/dump_ios/
// https://github.com/lichao890427/frida_script   analysis_hook.js  => submit issues

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

NSString = ObjC.classes.NSString;
NSFileManager = ObjC.classes.NSFileManager;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getNSString(str) {
    return NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}

function getStr(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr);
}

function getStrSize(addr, size) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr, size);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU8(addr);
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU8(addr, n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU16(addr);
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU16(addr, n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU32(addr, n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU64(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readPointer(addr);
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return Memory.writePointer(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

function dumpMemory(addr, length) {
    console.log(hexdump(Memory.readByteArray(addr, length), {
        offset: 0,
        length: length,
        header: true,
        ansi: true
    }));
}

NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
close = getExportFunction("f", "close", "int", ["int"]);

function getCacheDir() {
	var NSCachesDirectory = 13;
	var NSUserDomainMask = 1;
	var npdirs = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, 1);
	return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

// Export function
var modules = null;
function getAllAppModules() {
	if (modules == null) {
		modules = new Array();
		var tmpmods = Process.enumerateModulesSync();
		for (var i = 0; i < tmpmods.length; i++) {
			if (tmpmods[i].path.indexOf(".app") != -1) {
				modules.push(tmpmods[i]);
			}
		}
	}
	return modules;
}

var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

// You can dump .app or dylib (Encrypt/No Encrypt)
function dumpModule(name) {
	if (modules == null) {
		modules = getAllAppModules();
	}
	var targetmod = null;
	for (var i = 0; i < modules.length; i++) {
		if (modules[i].path.indexOf(name) != -1) {
			targetmod = modules[i];
			break;
		}
	}
	if (targetmod == null) {
		console.log("Cannot find module");
		return;
	}
	var modbase = modules[i].base;
	var modsize = modules[i].size;
	var newmodname = modules[i].name + ".decrypted";
	var newmodpath = getCacheDir() + "/" + newmodname;
	var oldmodpath = modules[i].path;
	
	var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
	var foldmodule = open(oldmodpath, O_RDONLY, 0);
	if (fmodule == -1 || foldmodule == -1) {
		console.log("Cannot open file" + newmodpath);
		return;
	}

	var BUFSIZE = 4096;
	var buffer = malloc(BUFSIZE);
	while (read(foldmodule, buffer, BUFSIZE)) {
		write(fmodule, buffer, BUFSIZE);
	}
	
	// Find crypt info and recover
	var is64bit = false;
	var size_of_mach_header = 0;
	var magic = getU32(modbase);
	if (magic == MH_MAGIC || magic == MH_CIGAM) {
		is64bit = false;
		size_of_mach_header = 28;
	}
	else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
		is64bit = true;
		size_of_mach_header = 32;
	}
	var ncmds = getU32(modbase.add(16));
	var off = size_of_mach_header;
	var offset_cryptoff = -1;
	var crypt_off = 0;
	var crypt_size = 0;
	var segments = [];
	for (var i = 0; i < ncmds; i++) {
		var cmd = getU32(modbase.add(off));
		var cmdsize = getU32(modbase.add(off + 4)); 
		if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
			offset_cryptoff = off + 8;
			crypt_off = getU32(modbase.add(off + 8));
			crypt_size = getU32(modbase.add(off + 12));
		}
		off += cmdsize;
	}

	if (offset_cryptoff != -1) {
		var tpbuf = malloc(8);
		console.log("Fix decrypted at:" + offset_cryptoff.toString(16));
		putU64(tpbuf, 0);
		lseek(fmodule, offset_cryptoff, SEEK_SET);
		write(fmodule, tpbuf, 8);
		console.log("Fix decrypted at:" + crypt_off.toString(16));
		lseek(fmodule, crypt_off, SEEK_SET);
		write(fmodule, modbase.add(crypt_off), crypt_size);
	}
	console.log("Decrypted file at:" + newmodpath + " 0x" + modsize.toString(16));
	close(fmodule);
	close(foldmodule);
}	

/*
	Usage:   dumpModule("BWA.app");   dumpModule("aaa.dylib")
	[iPhone::PID::20457]-> dumpModule(".app")
	Fix decrypted at:ac0
	Fix decrypted at:4000
*/
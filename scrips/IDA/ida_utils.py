from idaapi import *
def get_all_structs():
    #tranverse structures
    idx  = GetFirstStrucIdx()
    while idx != idaapi.BADADDR:
        sid = GetStrucId(idx)
        print "%d\t%x\t%s\t" % (idx, sid, GetStrucName(sid))  
        m = GetFirstMember(sid)
        while (m != -1 and m != idaapi.BADADDR):
            name = GetMemberName(sid, m)
            if name:
                print "\t+%x\t%x\t%s" % (m, GetMemberSize(sid, m), name)
            m = GetStrucNextOff(sid, m)    
        idx = GetNextStrucIdx(idx)

def get_all_localtypes():
    #traverse local types
    ml=GetMaxLocalType()
    for i in range(1, ml):
        print i, GetLocalType(i, 6)

def disasm_func(addr)
    #disassemble a function
    begin=GetFunctionAttr(addr,FUNCATTR_START)
    end=GetFunctionAttr(addr,FUNCATTR_END)
    while begin < end:
        print GetDisasm(begin)
        begin = begin + decode_insn(begin)

#for sk3wldbg
def setbpatcall(funcaddr):
    start=GetFunctionAttr(funcaddr,FUNCATTR_START)
    end=GetFunctionAttr(funcaddr,FUNCATTR_END)
    begin = start
    while begin < end:
        if GetMnem(begin) == "call":
            AddBpt(begin)
        begin = begin + decode_insn(begin)
    		
def sortfuncbysize(begin, end):
    addr=begin
    addr_map = {}
    while addr < end:
        addrnext = NextFunction(addr)
        addr_map[addr] = addrnext - addr
        addr = addrnext
    arr = sorted(addr_map.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
    for item in arr:
        print("%x-%x" % (item[0], item[1]))
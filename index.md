---
# CTF-Pwn 
--- 
**記錄一些pwn的技巧以及一些題目的解法，內容如果有錯麻煩告知會盡快修改XD。**

---

## study:
---
### ret2_dl_runtime:

需要對lazy binding 差不多熟悉, 以及會需要elf檔案的一些background
將一些library解析symbol的方式記錄起來


* lazy-binding & elf參考資料
  * [layz-binding](http://wthung2.blogspot.com/2010/03/elf-lazy-binding.html)
  * [glibc/elf/elf.h](https://code.woboq.org/userspace/glibc/elf/elf.h.html)

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
  * ![](https://i.imgur.com/hY0MUCe.png)
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
    * glibc/include/link.h https://code.woboq.org/userspace/glibc/include/link.h.html
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
  
###  Symbol Resolution 
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
## heap:
---
### unlink:

### uaf:

### double free:

### tcache:

### house_of_orange:

---
## kernel:

### basic knowledge


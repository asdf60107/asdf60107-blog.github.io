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
    ***
    * 所以可以印出來檢查

    ![](https://i.imgur.com/tTCSV4B.png)
    ***
    * 去比對一下用readelf抓出來的
    
    ![](https://i.imgur.com/3rdnlJ0.png)
    ***
    
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


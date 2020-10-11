---
# CTF-Pwn 
--- 
記錄一些pwn的技巧以及一些題目的解法，內容如果有錯麻煩告知會盡快修改XD。

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
- 對比一下source code
![](https://i.imgur.com/YfDGpcD.png)
* 由ELF Header那張圖可以看到Number of program headers 有9個而這個可以當array來印或是可以直接＠9就會直接印出九個program headers的內容。
  

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


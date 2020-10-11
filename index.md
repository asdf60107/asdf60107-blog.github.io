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
  *    readelf -a |\ less 
  
  segment : 由多個sections組合成一個

![](https://i.imgur.com/PdPn1PU.png)


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


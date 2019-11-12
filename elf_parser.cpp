#include "elf_parser.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "udis86.h"
static const std::string section_name_gnu_version_r = ".gnu.version_r";
static const std::string section_name_gnu_version = ".gnu.version";
static const std::string section_name_dynsym = ".dynsym";
static const std::string section_name_dynstr = ".dynstr";
static const std::string section_name_interp = ".interp";
static const std::string section_name_symtab = ".symtab";
static const std::string section_name_strtab = ".strtab";
static const std::string section_name_shstrtab = ".shstrtab";
static const std::string section_name_rela_dyn = ".rela.dyn";
static const std::string section_name_rela_plt = ".rela.plt";
static const std::string section_name_dynamic = ".dynamic";
static const std::string section_name_plt = ".plt";

Elf64_Parser::Elf64_Parser()
	: mem_(NULL),
	  ehdr_(NULL),
	  shdr_str_table_(NULL),
	  text_seg_sections_(),
	  data_seg_sections_(),
	  shdr_map_(),
	  vernaux_map_(),
	  gnu_ver_sym_vec_(),
	  dyn_sym_vec_(),
	  dyn_sym_name_vec_()
{

}

Elf64_Parser::~Elf64_Parser()
{

}

bool Elf64_Parser::load_elf_file_to_mem(const char *file_name)
{
	int fd;
	struct stat st;
	if ((fd = open(file_name, O_RDONLY)) == -1) {
		printf("open %s failed!\n", file_name);
		return false;
	}
	if (fstat(fd, &st) < 0) {
		printf("fstat %s failed!\n", file_name);
		return false;
	}

	mem_ = (uint8_t *)mmap(NULL,  st.st_size, PROT_READ,  MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == mem_) {
		printf("mmap failed!\n");
		return false;
	}
	ehdr_ = (Elf64_Ehdr *)mem_;
	_load_section_header_info();
	return true;
}

bool Elf64_Parser::is_elf64()
{
	if (ELFMAG0 != ehdr_->e_ident[EI_MAG0]) {
		printf("ELFMAG0 check error!\n");
		return false;
	}
	if (strncmp((const char *)&ehdr_->e_ident[EI_MAG1], "ELF", 3)) {
		printf("ELF magic check error!\n");
		return false;
	}

	if (ELFCLASS64 != ehdr_->e_ident[EI_CLASS]) {
		printf("is not a valid elf64 file format!\n");
		return false;
	}
	return true;
}


void Elf64_Parser::show_elf_header_info()
{
	printf("EI_DATA: ");
	switch (ehdr_->e_ident[EI_DATA]) {
		case ELFDATA2LSB:
			printf("little-endian\n");
			break;
		case ELFDATA2MSB:
			printf("big-endian\n");
			break;
		default:
			printf("unknown data format\n");
	}
	printf("EI_VERSION: ");
	switch (ehdr_->e_ident[EI_VERSION]) {
		case EV_NONE:
			printf("invalid version\n");
			break;
		case EV_CURRENT:
			printf("current version\n");
			break;
		default:
			printf("unknown\n");
			break;
	}

	switch (ehdr_->e_ident[EI_OSABI]) {
		case ELFOSABI_SYSV:
			printf("Unix System V ABI\n");
			break;
		case ELFOSABI_HPUX:
			printf("HPUX-ABI\n");
			break;
		case ELFOSABI_NETBSD:
			printf("NetBSD ABI\n");
			break;
		case ELFOSABI_LINUX:
			printf("Linux ABI\n");
			break;
		case ELFOSABI_SOLARIS:
			printf("Solaris ABI\n");
			break;
		case ELFOSABI_IRIX:
			printf("IRIX ABI\n");
			break;
		case ELFOSABI_FREEBSD:
			printf("FreeBSD ABI\n");
			break;
		case ELFOSABI_TRU64:
			printf("TRU64 UNIX ABI\n");
			break;
		case ELFOSABI_ARM:
			printf("ARM architecture ABI\n");
			break;
		case ELFOSABI_STANDALONE:
			printf("Stand-alone(embedded) ABI\n");
			break;
	}
	printf("EI_ABIVERSION: %x\n", ehdr_->e_ident[EI_ABIVERSION]);
	printf("e_type: ");
	switch (ehdr_->e_type) {
		case ET_REL:
			printf("A relocatable file_name\n");
			break;
		case ET_EXEC:
			printf("A executable file_name\n");
			break;
		case ET_DYN:
			printf("A shared object\n");
			break;
		case ET_CORE:
			printf("A core file_name\n");
			break;
		default:
			printf("A unknown file_name\n");
			break;
	}
	printf("e_machine: %x\n", ehdr_->e_machine);
	printf("e_version: %x\n", ehdr_->e_version);
	printf("e_entry: %lx\n", ehdr_->e_entry);
	printf("e_phoff: %ld\n", ehdr_->e_phoff);
	printf("e_shoff: %ld\n", ehdr_->e_shoff);
	printf("e_flags: %x\n", ehdr_->e_flags);
	printf("e_ehsize: %d\n", ehdr_->e_ehsize);
	printf("e_phentsize: %d\n", ehdr_->e_phentsize);
	printf("e_phnum: %d\n", ehdr_->e_phnum);
	printf("e_shentsize: %d\n", ehdr_->e_shentsize);
	printf("e_shnum: %d\n", ehdr_->e_shnum);
	printf("e_shstrndx: %d\n", ehdr_->e_shstrndx);
}


void Elf64_Parser::show_program_header_info()
{
	printf("-------------------program header -----------------------------\n");
	Elf64_Off phdr_offset = ehdr_->e_phoff;
	uint16_t phnum = ehdr_->e_phnum;
	Elf64_Phdr *phdr = (Elf64_Phdr *)&mem_[ehdr_->e_phoff];
	for (int i = 0; i < phnum; ++i) {
		printf("\t******************************\n");
		_show_phdr(phdr);
		phdr++;
	}
}

#define CASE_PT_TYPE(type) \
    case type: \
        printf("%s\n", #type); \
        break;


void Elf64_Parser::_show_phdr(Elf64_Phdr *phdr)
{
	printf("p_type: ");
	switch (phdr->p_type) {
		CASE_PT_TYPE(PT_NULL)
		CASE_PT_TYPE(PT_LOAD)
		CASE_PT_TYPE(PT_DYNAMIC)
		CASE_PT_TYPE(PT_INTERP)
		CASE_PT_TYPE(PT_NOTE)
		CASE_PT_TYPE(PT_SHLIB)
		CASE_PT_TYPE(PT_PHDR)
		CASE_PT_TYPE(PT_LOPROC)
		CASE_PT_TYPE(PT_HIPROC)
		CASE_PT_TYPE(PT_GNU_STACK)
		CASE_PT_TYPE(PT_TLS)
		CASE_PT_TYPE(PT_NUM)
		CASE_PT_TYPE(PT_LOOS)
		CASE_PT_TYPE(PT_GNU_EH_FRAME)
		CASE_PT_TYPE(PT_SUNWBSS)
		CASE_PT_TYPE(PT_HISUNW)
		CASE_PT_TYPE(PT_GNU_RELRO)
		default:
			printf("unknown\n");
			break;
	}
	printf("offset: %016lx\n", phdr->p_offset);
	printf("vaddr: %016lx\n", phdr->p_vaddr);
	printf("paddr: %016lx\n", phdr->p_paddr);
	printf("filesz: %016lx\n", phdr->p_filesz);
	printf("memsz: %016lx\n", phdr->p_memsz);
	printf("align: %lx\n", phdr->p_align);
	printf("flags: ");
	if (phdr->p_flags & PF_X) {
		printf("X");
	}
	if (phdr->p_flags & PF_W) {
		printf("W");
	}
	if (phdr->p_flags & PF_R) {
		printf("R");
	}
	printf("\n");
}



void Elf64_Parser::show_section_header_info()
{
	printf("-------------------section header -----------------------------\n");
	Elf64_Off shdr_offset = ehdr_->e_shoff;
	uint16_t shdr_num = ehdr_->e_shnum;
	Elf64_Shdr *shdr = (Elf64_Shdr *)&mem_[shdr_offset];
	Elf64_Half shdr_str_idx = ehdr_->e_shstrndx;
	shdr_str_table_ = (char *)&mem_[shdr[shdr_str_idx].sh_offset];
	for (int i = 0; i < shdr_num; ++i) {
		printf("\t******************************\n");
		printf("section name: %s\n", &shdr_str_table_[shdr->sh_name]);
		_show_shdr(shdr);
		shdr++;
	}
}

void Elf64_Parser::show_symtab_section_info()
{
	printf("-------------------symtab section -----------------------------\n");
	Elf64_Shdr *symtab_shdr = _get_section_header(section_name_symtab.c_str());
	if (!symtab_shdr) {
		printf("has not .symtab section\n");
		return;
	}
	Elf64_Shdr *strtab_shdr = _get_section_header(section_name_strtab.c_str());
	if (!strtab_shdr) {
		printf("has not .strtab section\n");
		return;
	}
	Elf64_Half symtab_ent_num = symtab_shdr->sh_size / symtab_shdr->sh_entsize;
	char *strtab_table = (char *)&mem_[strtab_shdr->sh_offset];
	Elf64_Sym *sym = (Elf64_Sym *)&mem_[symtab_shdr->sh_offset];
	for (Elf64_Half i = 0; i < symtab_ent_num; ++i) {
		printf("%d section name: %s\n", i, &strtab_table[sym->st_name]);
		sym++;
	}
}

Elf64_Half Elf64_Parser::_get_dynsym_gnu_ver_name(Elf64_Half index)
{
	if (index >= gnu_ver_sym_vec_.size()) {
		return 0;
	}
	Elf64_Half gnu_ver = gnu_ver_sym_vec_[index];
	auto vernaux_iter = vernaux_map_.find(gnu_ver);
	if (vernaux_iter == vernaux_map_.end()) {
		return 0;
	}
	return vernaux_iter->second->vna_name;
}

void Elf64_Parser::show_dynsym_section_info()
{
	_load_dynsym();
	for (auto i = 0; i < dyn_sym_name_vec_.size(); ++i) {
		printf("%d name: %s\n", i, dyn_sym_name_vec_[i].c_str());
	}
}

void Elf64_Parser::_load_dynsym()
{
	if (!dyn_sym_vec_.empty()) {
		return;
	}
	_load_gnu_version();
	_load_gnu_version_r();
	Elf64_Shdr *dynsym_shdr = _get_section_header(section_name_dynsym.c_str());
	if (!dynsym_shdr) {
		return;
	}
	Elf64_Shdr *dynstr_shdr = _get_section_header(section_name_dynstr.c_str());
	if (!dynstr_shdr) {
		return;
	}
	dyn_sym_vec_.clear();
	dyn_sym_name_vec_.clear();
	//dynstr string table
	char *dynstr_table = (char *)&mem_[dynstr_shdr->sh_offset];
	Elf64_Half dynsym_ent_num = dynsym_shdr->sh_size / dynsym_shdr->sh_entsize;
	Elf64_Sym *dyn_sym = (Elf64_Sym *)&mem_[dynsym_shdr->sh_offset];
	for (Elf64_Half i = 0; i < dynsym_ent_num; ++i) {
		dyn_sym_vec_.push_back(dyn_sym);
		Elf64_Half gnu_ver_name_index = _get_dynsym_gnu_ver_name(i);
		if (gnu_ver_name_index) {
			char tmp_buf[0x100] = { 0 };
			sprintf(tmp_buf, "%s@%s", &dynstr_table[dyn_sym->st_name], &dynstr_table[gnu_ver_name_index]);
			dyn_sym_name_vec_.push_back(tmp_buf);
		} else {
			dyn_sym_name_vec_.push_back(&dynstr_table[dyn_sym->st_name]);
		}
		dyn_sym++;
	}
}

void Elf64_Parser::show_interp_section_info()
{
	Elf64_Shdr *interp_shdr = _get_section_header(section_name_interp.c_str());
	if (!interp_shdr) {
		return;
	}
	printf("interp: %s\n", (char *)&mem_[interp_shdr->sh_offset]);
}

#define CASE_SHT_TYPE(type) \
    case type: \
        printf("%s\n", #type); \
        break;

void Elf64_Parser::_show_shdr(Elf64_Shdr *shdr)
{
	switch (shdr->sh_type) {
		CASE_SHT_TYPE(SHT_NULL)
		CASE_SHT_TYPE(SHT_PROGBITS)
		CASE_SHT_TYPE(SHT_SYMTAB)
		CASE_SHT_TYPE(SHT_STRTAB)
		CASE_SHT_TYPE(SHT_RELA)
		CASE_SHT_TYPE(SHT_HASH)
		CASE_SHT_TYPE(SHT_DYNAMIC)
		CASE_SHT_TYPE(SHT_NOTE)
		CASE_SHT_TYPE(SHT_NOBITS)
		CASE_SHT_TYPE(SHT_REL)
		CASE_SHT_TYPE(SHT_SHLIB)
		CASE_SHT_TYPE(SHT_DYNSYM)
		CASE_SHT_TYPE(SHT_LOPROC)
		CASE_SHT_TYPE(SHT_HIPROC)
		CASE_SHT_TYPE(SHT_LOUSER)
		CASE_SHT_TYPE(SHT_HIUSER)
	}
	printf("flags: ");
	if (shdr->sh_flags & SHF_WRITE) {
		printf("WRITE ");
	}
	if (shdr->sh_flags & SHF_ALLOC) {
		printf("ALLOC ");
	}
	if (shdr->sh_flags & SHF_EXECINSTR) {
		printf("SHF_EXECINSTR ");
	}
	if (shdr->sh_flags & SHF_MASKPROC) {
		printf("MASKPROC ");
	}
	printf("\n");
	printf("addr: %016lx\n", shdr->sh_addr);
	printf("offset: %08lx\n", shdr->sh_offset);
	printf("size: %016lx\n", shdr->sh_size);
	printf("entsize: %016lx\n", shdr->sh_entsize);
	printf("link: %lx\n", shdr->sh_link);
	printf("info: %lx\n", shdr->sh_info);
	printf("addralign: %lx\n", shdr->sh_addralign);
}


Elf64_Shdr* Elf64_Parser::_get_section_header(const char *sec_name)
{
	auto shdr_iter = shdr_map_.find(sec_name);
	if (shdr_iter == shdr_map_.end()) {
		printf("please load section header first!\n");
		return NULL;
	}
	return shdr_iter->second;
}

void Elf64_Parser::_load_section_header_info()
{
	Elf64_Off shdr_offset = ehdr_->e_shoff;
	uint16_t shdr_num = ehdr_->e_shnum;
	Elf64_Shdr *shdr = (Elf64_Shdr *)&mem_[shdr_offset];
	Elf64_Half shdr_str_idx = ehdr_->e_shstrndx;
	shdr_str_table_ = (char *)&mem_[shdr[shdr_str_idx].sh_offset];
	shdr_map_.clear();
	text_seg_sections_.clear();
	data_seg_sections_.clear();
	for (int i = 0; i < shdr_num; ++i) {
		shdr_map_[&shdr_str_table_[shdr->sh_name]] = shdr;
		if ((shdr->sh_flags & SHF_ALLOC) && !(shdr->sh_flags & SHF_WRITE)) {
			text_seg_sections_.push_back(&shdr_str_table_[shdr->sh_name]);
		}

		if ((shdr->sh_flags & SHF_ALLOC) && (shdr->sh_flags & SHF_WRITE)) {
			data_seg_sections_.push_back(&shdr_str_table_[shdr->sh_name]);
		}
		shdr++;
	}
}

bool Elf64_Parser::_load_gnu_version_r()
{
	if (!vernaux_map_.empty()) {
		return true;
	}
	auto gnu_version_r_shdr_iter = shdr_map_.find(section_name_gnu_version_r);
	if (gnu_version_r_shdr_iter == shdr_map_.end()) {
		printf("please load section header first!\n");
		return false;
	}
	vernaux_map_.clear();
	Elf64_Shdr *gnu_version_r_shdr = gnu_version_r_shdr_iter->second;
	Elf64_Verneed *verneed = (Elf64_Verneed *)&mem_[gnu_version_r_shdr->sh_offset];
	while (true) {
		Elf64_Vernaux *naux = (Elf64_Vernaux *)(verneed + 1);
		for (Elf64_Half i = 0; i < verneed->vn_cnt; ++i) {
			vernaux_map_[naux->vna_other] = naux;
			naux++;
		}

		Elf64_Word vn_next = verneed->vn_next;
		if (!vn_next) {
			break;
		}
		verneed = (Elf64_Verneed *)((char *)verneed + vn_next);
	}
	return true;
}

bool Elf64_Parser::_load_gnu_version()
{
	if (!gnu_ver_sym_vec_.empty()) {
		return true;
	}
	auto gnu_version_shdr_iter = shdr_map_.find(section_name_gnu_version);
	if (gnu_version_shdr_iter == shdr_map_.end()) {
		printf("please load section header first!\n");
		return false;
	}
	gnu_ver_sym_vec_.clear();
	Elf64_Shdr *gnu_version_shdr = gnu_version_shdr_iter->second;
	Elf64_Half gnu_ver_sym_num = gnu_version_shdr->sh_size / gnu_version_shdr->sh_entsize;
	Elf64_Half *ver_sym = (Elf64_Half *)&mem_[gnu_version_shdr->sh_offset];
	for (Elf64_Half i = 0; i < gnu_ver_sym_num; ++i) {
		gnu_ver_sym_vec_.push_back(*ver_sym);
		ver_sym++;
	}
	return true;
}

typedef struct plt_entry_asm {
	uint8_t data[16];
}plt_entry_asm;

/**
 * .plt节中存放的时PLT表，为GOT表的地址+重定位符号表（.rela.plt）的存根
 * 
 * @author chris (2019/11/12)
 */
void Elf64_Parser::show_plt_section_info() {
	printf("-------------------.plt section -----------------------------\n"); 
	Elf64_Shdr *plt_shdr = _get_section_header(section_name_plt.c_str());
	if (!plt_shdr) {
		printf("has no .plt section\n");
		return;
	}
	_show_shdr(plt_shdr);
	Elf64_Half plt_entry_num = plt_shdr->sh_size / plt_shdr->sh_entsize;
	printf(".plt entry num: %ld\n", plt_entry_num);
	plt_entry_asm *plt_data = (plt_entry_asm *)&mem_[plt_shdr->sh_offset];
	for (Elf64_Half i = 0; i < plt_entry_num;++i) {
		ud_t ud_object;
		ud_init(&ud_object);
		ud_set_input_buffer(&ud_object, plt_data->data, sizeof(plt_entry_asm));
		ud_set_mode(&ud_object, 64);
		ud_set_syntax(&ud_object, UD_SYN_INTEL);
		while (ud_disassemble(&ud_object)) {
			printf("\t%s\n", ud_insn_asm(&ud_object));
		}
		printf("\n");
		plt_data++;
	}
}



#define CASE_DYN_TYPE(type) \
	case type: \
		printf("%-15s\t\t\t", #type); \
		break;

void Elf64_Parser::show_dynamic_section_info() {
	printf("-------------------.dynamic section -----------------------------\n");
	Elf64_Shdr *dynamic_shdr = _get_section_header(section_name_dynamic.c_str());
	if (!dynamic_shdr){
		printf("has no .dynamic section\n");
		return;
	}
	_show_shdr(dynamic_shdr);
	printf("%-15s\t\t\tName/Value\n","TYPE");
	Elf64_Half dynamic_ent_num = dynamic_shdr->sh_size / dynamic_shdr->sh_entsize;
	Elf64_Dyn *dyn = (Elf64_Dyn *)&mem_[dynamic_shdr->sh_offset];
	for (Elf64_Half i = 0; i < dynamic_ent_num; ++i){
		switch (dyn->d_tag) {
			CASE_DYN_TYPE( DT_NULL)
			CASE_DYN_TYPE(DT_NEEDED)
			CASE_DYN_TYPE(DT_PLTRELSZ)
			CASE_DYN_TYPE(DT_PLTGOT)
			CASE_DYN_TYPE(DT_HASH)
			CASE_DYN_TYPE(DT_STRTAB)
			CASE_DYN_TYPE(DT_SYMTAB)
			CASE_DYN_TYPE(DT_RELA)
			CASE_DYN_TYPE(DT_RELASZ)
			CASE_DYN_TYPE(DT_RELAENT)
			CASE_DYN_TYPE(DT_STRSZ)
			CASE_DYN_TYPE(DT_SYMENT)
			CASE_DYN_TYPE(DT_INIT)
			CASE_DYN_TYPE(DT_FINI)
			CASE_DYN_TYPE(DT_SONAME)
			CASE_DYN_TYPE(DT_RPATH)
			CASE_DYN_TYPE(DT_SYMBOLIC)
			CASE_DYN_TYPE(DT_REL)
			CASE_DYN_TYPE(DT_RELSZ)
			CASE_DYN_TYPE(DT_RELENT)
			/**
			 *  Type of reloc in plt
			 *  R_X86_64_JUMP_SLO
			 */
			CASE_DYN_TYPE(DT_PLTREL) 
			CASE_DYN_TYPE(DT_DEBUG)
			CASE_DYN_TYPE(DT_TEXTREL)
			CASE_DYN_TYPE(DT_JMPREL)
			CASE_DYN_TYPE(DT_BIND_NOW)
			CASE_DYN_TYPE(DT_INIT_ARRAY)
			CASE_DYN_TYPE(DT_FINI_ARRAY)
			CASE_DYN_TYPE(DT_INIT_ARRAYSZ)
			CASE_DYN_TYPE(DT_FINI_ARRAYSZ)
			CASE_DYN_TYPE(DT_RUNPATH)
			CASE_DYN_TYPE(DT_PREINIT_ARRAY)
			CASE_DYN_TYPE(DT_PREINIT_ARRAYSZ)
			CASE_DYN_TYPE(DT_LOOS)
			CASE_DYN_TYPE(DT_HIOS)
			CASE_DYN_TYPE(DT_LOPROC)
			CASE_DYN_TYPE(DT_HIPROC)
			CASE_DYN_TYPE(DT_PROCNUM)
			CASE_DYN_TYPE(DT_VALRNGLO)
			CASE_DYN_TYPE(DT_GNU_PRELINKED)
			CASE_DYN_TYPE(DT_GNU_CONFLICTSZ)
			CASE_DYN_TYPE(DT_GNU_LIBLISTSZ)
			CASE_DYN_TYPE(DT_CHECKSUM)
			CASE_DYN_TYPE(DT_PLTPADSZ)
			CASE_DYN_TYPE(DT_MOVEENT)
			CASE_DYN_TYPE(DT_FEATURE_1)
			CASE_DYN_TYPE(DT_SYMINSZ)
			CASE_DYN_TYPE(DT_SYMINENT)
			CASE_DYN_TYPE(DT_ADDRRNGLO)
			CASE_DYN_TYPE(DT_GNU_HASH)
			CASE_DYN_TYPE(DT_TLSDESC_PLT)
			CASE_DYN_TYPE(DT_TLSDESC_GOT)
			CASE_DYN_TYPE(DT_GNU_CONFLICT)
			CASE_DYN_TYPE(DT_GNU_LIBLIST)
			CASE_DYN_TYPE(DT_CONFIG)
			CASE_DYN_TYPE(DT_DEPAUDIT)
			CASE_DYN_TYPE(DT_AUDIT)
			CASE_DYN_TYPE(DT_PLTPAD)
			CASE_DYN_TYPE(DT_MOVETAB)
			CASE_DYN_TYPE(DT_SYMINFO)
			CASE_DYN_TYPE(DT_VERSYM)
			CASE_DYN_TYPE(DT_RELACOUNT)
			CASE_DYN_TYPE(DT_FLAGS_1)
			CASE_DYN_TYPE(DT_VERDEF)
			CASE_DYN_TYPE(DT_VERDEFNUM)
			CASE_DYN_TYPE(DT_VERNEED)
			CASE_DYN_TYPE(DT_VERNEEDNUM)
			CASE_DYN_TYPE(DT_AUXILIARY)
		}
		char *dyn_str_table = NULL;
		Elf64_Shdr *dyn_str_shdr = _get_section_header(section_name_dynstr.c_str());
		if (dyn_str_shdr) {
			dyn_str_table = (char *)&mem_[dyn_str_shdr->sh_offset];
		}
		switch (dyn->d_tag) {
			case DT_NEEDED:
				if (dyn_str_table) {
					printf("shared library: [%s]\n", &dyn_str_table[dyn->d_un.d_val]);
				}
				break;
			case DT_INIT_ARRAYSZ:
			case DT_FINI_ARRAYSZ:
			case DT_STRSZ:
			case DT_SYMENT:
			case DT_PLTRELSZ:
			case DT_RELASZ:
			case DT_RELAENT:
				printf("%ld (bytes)\n", dyn->d_un.d_val);
				break;
			case DT_VERNEEDNUM:
				printf("%ld\n", dyn->d_un.d_val);
				break;
			default:
				printf("0x%lx\n", dyn->d_un.d_val, dyn->d_un.d_ptr);
				break;
		}
		
		dyn++;
	}
}

void Elf64_Parser::show_relocs_section_info() {
	printf("-------------------relocs info -----------------------------\n");
	_show_rela_dyn_section_info();
	_show_rela_plt_section_info();
}

#define CASE_R_X86_64_TYPE(type) \
	case type: \
		printf( "type: %s\n",  #type);\
		break;

void Elf64_Parser::_show_rela_dyn_section_info()
{
	_load_dynsym();
	printf("-------------------.rela.dyn section -----------------------------\n");
	Elf64_Shdr *rela_dyn_shdr = _get_section_header(section_name_rela_dyn.c_str());
	if (!rela_dyn_shdr) {
		printf("has no .rela.dyn section\n");
		return;
	}
	_show_shdr(rela_dyn_shdr);
	Elf64_Half rela_dyn_ent_num = rela_dyn_shdr->sh_size / rela_dyn_shdr->sh_entsize;
	printf(".rela.dyn entry num=%d\n", rela_dyn_ent_num);
	//TODO
	if (rela_dyn_shdr->sh_entsize != sizeof(Elf64_Rela)) {
		printf("is not Elf64_Rela type\n");
		return;
	}
	Elf64_Rela *rela = (Elf64_Rela *)&mem_[rela_dyn_shdr->sh_offset];
	for (Elf64_Half i = 0; i < rela_dyn_ent_num; ++i) {
		printf("\n");
		printf("sym index: %d\n", ELF64_R_SYM(rela->r_info));
		printf("Sym.Value  %016lx\n", dyn_sym_vec_[ELF64_R_SYM(rela->r_info)]->st_value);
		printf("Sym.name + Addend: %s + %lx\n", dyn_sym_name_vec_[ELF64_R_SYM(rela->r_info)].c_str(), rela->r_addend);
		printf("r_offset: %016lx\n", rela->r_offset);
		switch (ELF64_R_TYPE(rela->r_info)) {
			CASE_R_X86_64_TYPE(R_X86_64_NONE)
			CASE_R_X86_64_TYPE(R_X86_64_64)
			CASE_R_X86_64_TYPE(R_X86_64_PC32)
			CASE_R_X86_64_TYPE(R_X86_64_GOT32)
			CASE_R_X86_64_TYPE(R_X86_64_PLT32)
			CASE_R_X86_64_TYPE(R_X86_64_COPY)
			CASE_R_X86_64_TYPE(R_X86_64_GLOB_DAT)
			CASE_R_X86_64_TYPE(R_X86_64_JUMP_SLOT)
			CASE_R_X86_64_TYPE(R_X86_64_RELATIVE)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPCREL)
			CASE_R_X86_64_TYPE(R_X86_64_32)
			CASE_R_X86_64_TYPE(R_X86_64_32S)
			CASE_R_X86_64_TYPE(R_X86_64_16)
			CASE_R_X86_64_TYPE(R_X86_64_PC16)
			CASE_R_X86_64_TYPE(R_X86_64_8)
			CASE_R_X86_64_TYPE(R_X86_64_PC8)
			CASE_R_X86_64_TYPE(R_X86_64_DTPMOD64)
			CASE_R_X86_64_TYPE(R_X86_64_DTPOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_TPOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_TLSGD)
			CASE_R_X86_64_TYPE(R_X86_64_TLSLD)
			CASE_R_X86_64_TYPE(R_X86_64_DTPOFF32)
			CASE_R_X86_64_TYPE(R_X86_64_GOTTPOFF)
			CASE_R_X86_64_TYPE(R_X86_64_TPOFF32)
			CASE_R_X86_64_TYPE(R_X86_64_PC64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC32)
			CASE_R_X86_64_TYPE(R_X86_64_GOT64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPCREL64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPLT64)
			CASE_R_X86_64_TYPE(R_X86_64_PLTOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_SIZE32)
			CASE_R_X86_64_TYPE(R_X86_64_SIZE64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC32_TLSDESC)
			CASE_R_X86_64_TYPE(R_X86_64_TLSDESC_CALL)
			CASE_R_X86_64_TYPE(R_X86_64_TLSDESC)
			CASE_R_X86_64_TYPE(R_X86_64_RELATIVE64)
			default:
				printf("TYPE: unknown\n");
				break;
		}
		rela++;
	}
}


void Elf64_Parser::_show_rela_plt_section_info()
{
	_load_dynsym();
	printf("-------------------.rela.plt section -----------------------------\n");
	Elf64_Shdr *rela_plt_shdr = _get_section_header(section_name_rela_plt.c_str());
	if (!rela_plt_shdr) {
		printf("has no .rela.plt section\n");
		return;
	}
	_show_shdr(rela_plt_shdr);
	Elf64_Half rela_plt_ent_num = rela_plt_shdr->sh_size / rela_plt_shdr->sh_entsize;
	printf(".rela.plt entry num=%d\n", rela_plt_ent_num);
	if (rela_plt_shdr->sh_entsize != sizeof(Elf64_Rela)) {
		printf("is not Elf64_Rela type\n");
		return;
	}
	Elf64_Rela *rela = (Elf64_Rela *)&mem_[rela_plt_shdr->sh_offset];
	for (Elf64_Half i = 0; i < rela_plt_ent_num; ++i) {
		printf("\n");
		printf("sym index: %d\n", ELF64_R_SYM(rela->r_info));
		printf("Sym.Value  %016lx\n", dyn_sym_vec_[ELF64_R_SYM(rela->r_info)]->st_value);
		printf("Sym.name + Addend: %s + %lx\n", dyn_sym_name_vec_[ELF64_R_SYM(rela->r_info)].c_str(), rela->r_addend);
		printf("r_offset: %016lx\n", rela->r_offset);
		switch (ELF64_R_TYPE(rela->r_info)) {
			CASE_R_X86_64_TYPE(R_X86_64_NONE)
			CASE_R_X86_64_TYPE(R_X86_64_64)
			CASE_R_X86_64_TYPE(R_X86_64_PC32)
			CASE_R_X86_64_TYPE(R_X86_64_GOT32)
			CASE_R_X86_64_TYPE(R_X86_64_PLT32)
			CASE_R_X86_64_TYPE(R_X86_64_COPY)
			CASE_R_X86_64_TYPE(R_X86_64_GLOB_DAT)
			CASE_R_X86_64_TYPE(R_X86_64_JUMP_SLOT)
			CASE_R_X86_64_TYPE(R_X86_64_RELATIVE)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPCREL)
			CASE_R_X86_64_TYPE(R_X86_64_32)
			CASE_R_X86_64_TYPE(R_X86_64_32S)
			CASE_R_X86_64_TYPE(R_X86_64_16)
			CASE_R_X86_64_TYPE(R_X86_64_PC16)
			CASE_R_X86_64_TYPE(R_X86_64_8)
			CASE_R_X86_64_TYPE(R_X86_64_PC8)
			CASE_R_X86_64_TYPE(R_X86_64_DTPMOD64)
			CASE_R_X86_64_TYPE(R_X86_64_DTPOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_TPOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_TLSGD)
			CASE_R_X86_64_TYPE(R_X86_64_TLSLD)
			CASE_R_X86_64_TYPE(R_X86_64_DTPOFF32)
			CASE_R_X86_64_TYPE(R_X86_64_GOTTPOFF)
			CASE_R_X86_64_TYPE(R_X86_64_TPOFF32)
			CASE_R_X86_64_TYPE(R_X86_64_PC64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC32)
			CASE_R_X86_64_TYPE(R_X86_64_GOT64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPCREL64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPLT64)
			CASE_R_X86_64_TYPE(R_X86_64_PLTOFF64)
			CASE_R_X86_64_TYPE(R_X86_64_SIZE32)
			CASE_R_X86_64_TYPE(R_X86_64_SIZE64)
			CASE_R_X86_64_TYPE(R_X86_64_GOTPC32_TLSDESC)
			CASE_R_X86_64_TYPE(R_X86_64_TLSDESC_CALL)
			CASE_R_X86_64_TYPE(R_X86_64_TLSDESC)
			CASE_R_X86_64_TYPE(R_X86_64_RELATIVE64)
			default:
				printf("TYPE: unknown\n");
				break;
		}
		rela++;
	}
}

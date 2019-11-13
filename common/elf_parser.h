#ifndef __ELF_PARSER_H__
#define __ELF_PARSER_H__
#include <elf.h>
#include <string>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <map>
class Elf64_Parser {
public:
    Elf64_Parser();
    ~Elf64_Parser();
public:
    bool load_elf_file_to_mem(const char *file_name);
    bool is_elf64();
    void show_elf_header_info();
    void show_program_header_info();
    void show_section_header_info();
    void show_dynsym_section_info();
    void show_interp_section_info();
    void show_symtab_section_info();
    void show_relocs_section_info();
    void show_dynamic_section_info();
    void show_plt_section_info();
    void show_plt_got_section_info();
    void show_got_plt_section_info();
    void show_got_section_info();
    void load_symtab_section();
    Elf64_Addr lookup_symbol(const char *symname);
private:
    Elf64_Shdr* _get_section_header(const char *sec_name);
    void _show_phdr(Elf64_Phdr *phdr);
    void _show_shdr(Elf64_Shdr *shdr);
    void _load_section_header_info(); 
    bool _load_gnu_version_r();
    bool _load_gnu_version();
    Elf64_Half _get_dynsym_gnu_ver_name(Elf64_Half index);
    void _show_rela_dyn_section_info();
    void _show_rela_plt_section_info();
    void _load_dynsym();
private:
    uint8_t *mem_;
    Elf64_Ehdr *ehdr_;
    char *shdr_str_table_;
    std::vector<std::string> text_seg_sections_;
    std::vector<std::string> data_seg_sections_;
    std::map<std::string, Elf64_Shdr *> shdr_map_;
    std::map<Elf64_Half, Elf64_Vernaux *> vernaux_map_;
    std::vector<Elf64_Half> gnu_ver_sym_vec_;
    std::vector<Elf64_Sym *> dyn_sym_vec_;
    std::vector<std::string> dyn_sym_name_vec_;
    std::map<std::string, Elf64_Sym *> symtab_map_;
};
#endif

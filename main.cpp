#include <iostream>
#include "elf_parser.h"
int main(int argc,  char **argv) {
    if(argc<2) {
        printf("elf_parser  elf_file\n");
        return 1;
    }
    Elf64_Parser parser;
    bool ret=parser.load_elf_file_to_mem(argv[1]);
    if(!ret) {
        return 1;
    }
    ret = parser.is_elf64();
    if(!ret) {
        return 1;
    }
    //parser.show_dynsym_section_info();
    //parser.show_interp_section_info();
    //parser.show_elf_header_info();
    //parser.show_program_header_info();
    //parser.show_section_header_info();
    //parser.show_symtab_section_info();
    //parser.show_relocs_section_info();
    //parser.show_dynamic_section_info();
    parser.show_plt_section_info();
    return 0;
}

#include <iostream>
#include <string.h>
#include <elf.h>
#include <stdio.h>
#define CASE_AUXT_TYPE(type)        \
    case type:                      \
        printf("%-15s\t\t", #type); \
        break;
void stack_flow()
{
    int a = 32;
    int array[3];
    memset(array, 0, 3 * sizeof(int));
    std::cout << a << std::endl;
}

int main(int argc, char** argv, char** envp)
{
    Elf64_auxv_t* auxv;
    while (*envp++ != NULL) {
        /*
        if (*envp)
            printf("%s\n", *envp);
            */
    }
    printf("%-15s\t\tValue\n", "Type");
    for (auxv = (Elf64_auxv_t*)envp; auxv->a_type != AT_NULL; auxv++) {
        switch (auxv->a_type) {
            CASE_AUXT_TYPE(AT_NULL)
            CASE_AUXT_TYPE(AT_IGNORE)
            CASE_AUXT_TYPE(AT_EXECFD)
            CASE_AUXT_TYPE(AT_PHDR)
            CASE_AUXT_TYPE(AT_PHENT)
            CASE_AUXT_TYPE(AT_PHNUM)
            CASE_AUXT_TYPE(AT_PAGESZ)
            CASE_AUXT_TYPE(AT_BASE)
            CASE_AUXT_TYPE(AT_FLAGS)
            CASE_AUXT_TYPE(AT_ENTRY)
            CASE_AUXT_TYPE(AT_NOTELF)
            CASE_AUXT_TYPE(AT_UID)
            CASE_AUXT_TYPE(AT_EUID)
            CASE_AUXT_TYPE(AT_GID)
            CASE_AUXT_TYPE(AT_EGID)
            CASE_AUXT_TYPE(AT_CLKTCK)
            CASE_AUXT_TYPE(AT_PLATFORM)
            CASE_AUXT_TYPE(AT_HWCAP)
            CASE_AUXT_TYPE(AT_DCACHEBSIZE)
            CASE_AUXT_TYPE(AT_ICACHEBSIZE)
            CASE_AUXT_TYPE(AT_UCACHEBSIZE)
            CASE_AUXT_TYPE(AT_IGNOREPPC)
            CASE_AUXT_TYPE(AT_SECURE)
            CASE_AUXT_TYPE(AT_BASE_PLATFORM)
            CASE_AUXT_TYPE(AT_RANDOM)
            CASE_AUXT_TYPE(AT_HWCAP2)
            CASE_AUXT_TYPE(AT_SYSINFO)
            CASE_AUXT_TYPE(AT_SYSINFO_EHDR)
            CASE_AUXT_TYPE(AT_L1I_CACHESHAPE)
            CASE_AUXT_TYPE(AT_L1D_CACHESHAPE)
            CASE_AUXT_TYPE(AT_L2_CACHESHAPE)
            CASE_AUXT_TYPE(AT_L3_CACHESHAPE)
            CASE_AUXT_TYPE(AT_EXECFN)
        }
        switch (auxv->a_type) {
        case AT_EXECFN:
            printf("%s\n", (char*)auxv->a_un.a_val);
            break;
        default:
            printf("%016lx\n", auxv->a_un.a_val);
            break;
        }
    }
    stack_flow();
    std::cout << "Hello world" << std::endl;
    while(1){}
    return 0;
}

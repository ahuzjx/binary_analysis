#include <stdio.h>
void print_string(const char* str){
    printf("%s\n",str);
}

int main()
{
    print_string("Hello 1");
    print_string("Hello 2");
    print_string("Hello 3");
    printf("Hello world\n");
    return 0;
}


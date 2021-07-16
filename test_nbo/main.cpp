#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
int main(int argc, char *argv[]){
    FILE *fp,*fp2;
    uint32_t thousand,five_hundred;
    // read binary file

    fp = fopen(argv[1], "rb");
    fread(&thousand, sizeof(uint32_t),1, fp);
    fp2 = fopen(argv[2], "rb");
    fread(&five_hundred, sizeof(uint32_t),1, fp2);

    // print
    printf("%02x\n",ntohl(thousand) + ntohl(five_hundred));
    fclose(fp); }

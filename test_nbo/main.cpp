#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
int file_read(char num[])
{
    FILE *fp;
    uint32_t snum;
    fp = fopen(num, "rb");
    fread(&snum, sizeof(uint32_t),1, fp);
    fclose(fp);
    return ntohl(snum);
}

int main(int argc, char *argv[]){
    if(argc !=3)
    {
        printf("error!");
        return 0;
    }
    uint32_t sum = file_read(argv[1])+file_read(argv[2]);
    printf("%02x = %d",sum,sum);

     }

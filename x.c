#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>

void replacestr(char *str)
{
    int i;
    i = strlen(str);
    
    while(i >= 0) {
        if(str[i] == '/')
            str[i] = '_';
        i--;
    }
}

int main(void)
{
    FILE *f, *fo;
    u_int16_t nbf = 0, i = 0;
    u_int32_t nbr, sbuf;
    long pos = 0;
    char fname[65];
    char fbuf[65535];
    
    struct __attribute__((packed)) filerecord {
        u_int32_t p_fname;
        u_int32_t p_data;
        u_int32_t len;
        u_int32_t ts;
        u_int32_t mt;
        u_int16_t flags;
    };
    struct filerecord *filerecords;

    f = fopen("PE8_1.6.159.bin", "rb");

    /* Get number of files */
    fseek(f, 4 + 2, SEEK_SET);
    fread(&nbf, sizeof(nbf), 1, f);
    printf("nbfiles = %d\n", nbf);

    /* Skip file hashes */
    fseek(f, nbf*2, SEEK_CUR); 

    /* Get file records */
    filerecords=malloc(sizeof(struct filerecord)*nbf);

    pos = ftell(f);
    for (i = 0; i < nbf; i++) {
        printf("file no %d (pos: %X):\n", i, pos);
        fseek(f, pos, SEEK_SET);
        fread(&filerecords[i], sizeof(struct filerecord), 1, f);
        printf("Pointer to filename: 0x%X\n", filerecords[i].p_fname);
        printf("Pointer to data: 0x%X\n", filerecords[i].p_data);
        printf("Data length: 0x%X\n", filerecords[i].len);
        printf("Timestamp: 0x%X\n", filerecords[i].ts);
        printf("Microtime: 0x%X\n", filerecords[i].mt);
        printf("Flags: 0x%X\n", filerecords[i].flags);
        pos = ftell(f);
        
        fseek(f, filerecords[i].p_fname, SEEK_SET);
        bzero(fname, sizeof(fname));
        fread(fname, 64, 1, f);
        if (strlen(fname) == 0)
            sprintf(fname, "file@%0.8X", filerecords[i].p_fname);
        replacestr(fname);
        printf("%s\n", fname);

        fseek(f, filerecords[i].p_data, SEEK_SET);
        fo = fopen(fname, "wb");
        nbr = 0;
        while (nbr < filerecords[i].len) {
            if ((filerecords[i].len - nbr) > 65535)
                sbuf = 65535;
            else
                sbuf = filerecords[i].len - nbr;
            nbr += fread(fbuf, 1, filerecords[i].len - nbr, f);
            printf("Data read: 0x%X\n", nbr);
            fwrite(fbuf, nbr, 1, fo);
        }
        fclose(fo);
        printf("----\n", i, pos);
    }

    free(filerecords);
    fclose(f);
    return 0;
}

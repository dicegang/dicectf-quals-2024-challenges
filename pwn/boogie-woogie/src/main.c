#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>

// generate art.h with echo "const unsigned char __art[] = {$((ascii-image-converter ./aoi-todo.webp  --color --dither --braille --width 80; echo -ne "\x00") | xxd -i)};" > art.h
#include "art.h"

char data[] = {"Listen closely, cursed spirit. There is no way you do not know this. An arm is\nmerely a decoration. The act of applause is an acclamation of the soul!"};

void clap(size_t a, size_t b)
{
    data[a] ^= data[b];
    data[b] ^= data[a];
    data[a] ^= data[b];
}

// gcc main.c -o boogie-woogie
int main()
{
    // set line buffering. comment this to let libc decide when to buffer (based on pty)
    // setvbuf(dlsym(NULL, "stdout"), NULL, _IOLBF, 0);

    printf("%s\n", __art);
    printf("\x1b[0;33mEven this cursed spirit uses Black Flash. The one who is now being left behind\nis me. You’ve gotten strong, brother. Are you gonna just sit still, \x1b[4;33mAoi Todo\x1b[0;33m?!\nAre you gonna let your brother feel alone again, \x1b[4;33mAoi Todo\x1b[0;33m?!\x1b[0m\n\n");
    while (data[0])
    {
        size_t a, b = 0;
        printf("\n\x1b[31;49;1;4m%s\x1b[0m\n\n\n", data);

        printf("The sound of \x1b[0;33mgion shoja bells\x1b[0m echoes the impermanence of all things. The color\nof \x1b[0;33msala flowers\x1b[0m reveals the truth that the prosperous must decline. \x1b[4;33mHowever\x1b[0m! We\nare the exception:\n");
        scanf("%zu %zu", &a, &b);
        clap(a, b);
    }
}
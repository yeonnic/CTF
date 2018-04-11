#include<stdio.h>
#include<stdlib.h>
#include<time.h>

void swap(int*a, int*b){
    int tmp = *a;
    *a = *b;
    *b = tmp;
    return;
}

void rand_swap(int *a1, int size){
    int v3, v4,  i, j;
    srand(time(0));

    for( i = size*size-1; i>0; --i){
        v3 = rand();
        swap((int*)(i + a1), (int *)(a1 + v3 % (i + 1)));
    }
    for ( j = size * size - 1; j > 0; --j )
    {
    v4 = rand();
    swap((int*)(j + a1), (int*)(a1 + v4 % (j + 1)));
    }
}

int main(int argc, char **argv){

    if(argc !=2){
        return 0;
    }
    int size = atoi(argv[1]);

    int *s = malloc(0x10 * ((size * size + 0xF) / 0x10 * 4));

      for (int i = 1; size * size / 2 + 1 > i; ++i )
    {
    *((int*)s + 2 * (i - 1)) = i;
    *((int*)s + 2 * (i - 1) + 1) = i;
  }
    
    rand_swap(s, size);

    for(int i=0; i<size*size; ++i){
        printf("%x, ", s[i]);
    }
    printf("\n");
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// TEST Arrays

struct ArrayTest1 {
  unsigned int array1[16];
  void * ptr2;
  char char3;
  unsigned int array4[16];
  void * ptr5;
};


int test1(){
  struct ArrayTest1 * node;
  node = (struct ArrayTest1 *) malloc(sizeof(struct ArrayTest1));
  node->ptr2 = node;
  node->ptr5 = node;
  node->char3 = 'X';

  printf("o: test1 %p\n", node);

  return 0;
}


int main(){

  // TEST
  test1();

  printf("pid %u\n",getpid());
  fflush(stdout);
  sleep(-1);

  return 0;
}



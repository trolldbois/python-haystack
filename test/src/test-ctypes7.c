#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// TEST ZONE

struct Node {
  unsigned int val1;
  void * ptr2;
};


int test1(){
  struct Node * node;
  node = (struct Node *) malloc(sizeof(struct Node));
  node->val1 = 0xdeadbeef;
  node->ptr2 = node;
  printf("test1 %p\n", node);
  
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



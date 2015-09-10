/*
    Linked list tests.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct entry Entry;

struct entry {
  Entry * flink;
  Entry * blink;
};


struct usual
{
  unsigned int val1;
  unsigned int val2;
  Entry root;
  char txt[128];
  unsigned int val2b;
  unsigned int val1b;
};

struct Node
{
  unsigned int val1;
  Entry list;
  unsigned int val2;
};



int test1(){

  struct usual * usual;
  usual = (struct usual *) malloc(sizeof(struct usual));
  strcpy(usual->txt, "This a string with a test this is a test string");
  usual->val1 = 0x0aaaaaaa;
  usual->val2 = 0x0ffffff0;

  struct Node * node1;
  struct Node * node2;
  node1 = (struct Node *) malloc(sizeof(struct Node));
  node1->val1 = 0xdeadbeef;
  node1->val2 = 0xffffffff;
  node2 = (struct Node *) malloc(sizeof(struct Node));
  node2->val1 = 0xdeadbabe;
  node2->val2 = 0xffffffff;

  node1->list.flink = &node2->list;
  node1->list.blink = (struct entry *) 0;

  node2->list.flink = (struct entry *) 0;
  node2->list.blink = &node1->list;

  usual->root.flink = &node1->list;
  usual->root.blink = &node1->list;

  printf("o: test1 %p\n", usual);
  printf("o: test2 %p\n", node1);
  printf("o: test3 %p\n", node2);

  return 0;
}

int test_double_iter(){

  struct Node * nodes[32];

  for (int i=0;i<32;i++){
    nodes[i] = (struct Node *) malloc(sizeof(struct Node));
    nodes[i]->val1 = i;
    nodes[i]->val2 = i;
    nodes[i]->list.flink = 0x0;
    nodes[i]->list.blink = 0x0;
  }

  // we need complex cases
  // case A)
  // 7 nodes
  //   3 elements in flink of root, blink null
  //   3 different elements in blink of root, flink null
  nodes[0]->list.flink = &nodes[1]->list;
  nodes[1]->list.flink = &nodes[2]->list;
  nodes[2]->list.flink = &nodes[3]->list;
  nodes[3]->list.flink = 0x0;
  nodes[0]->list.blink = &nodes[4]->list;
  nodes[4]->list.blink = &nodes[5]->list;
  nodes[5]->list.blink = &nodes[6]->list;
  nodes[6]->list.blink = 0x0;

  // case B)
  //   a Full tree with 3 elements depth
  // 15 nodes
  // rootB
  nodes[7]->list.flink = &nodes[8]->list;
  nodes[8]->list.flink = &nodes[9]->list;
  nodes[9]->list.flink = &nodes[10]->list;
  nodes[9]->list.blink = &nodes[11]->list;
  // nodes[10].f/blink is x2 NULLs
  // nodes[11].f/blink is x2 NULLs
  nodes[8]->list.blink = &nodes[12]->list;
  nodes[12]->list.flink = &nodes[13]->list;
  nodes[12]->list.blink = &nodes[14]->list;
  // nodes[13].f/blink is x2 NULLs
  // nodes[14].f/blink is x2 NULLs

  nodes[7]->list.blink = &nodes[15]->list;
  nodes[15]->list.flink = &nodes[16]->list;
  nodes[16]->list.flink = &nodes[17]->list;
  nodes[16]->list.blink = &nodes[18]->list;
  // nodes[17].f/blink is x2 NULLs
  // nodes[18].f/blink is x2 NULLs
  nodes[15]->list.blink = &nodes[19]->list;
  nodes[19]->list.flink = &nodes[20]->list;
  nodes[19]->list.blink = &nodes[21]->list;
  // nodes[20].f/blink is x2 NULLs
  // nodes[21].f/blink is x2 NULLs

  // case C)
  //   a circular graph of sort
  // 32 nodes
  // rootB
  nodes[22]->list.flink = &nodes[23]->list;
  nodes[23]->list.flink = &nodes[24]->list;
  nodes[24]->list.flink = &nodes[25]->list;
  // get all nodes
  nodes[25]->list.flink = &nodes[0]->list;
  nodes[25]->list.blink = &nodes[7]->list;
  // loop backwards
  nodes[24]->list.blink = &nodes[23]->list;
  nodes[23]->list.flink = &nodes[26]->list;
  nodes[26]->list.flink = &nodes[27]->list;
  nodes[27]->list.flink = &nodes[28]->list;
  nodes[28]->list.flink = &nodes[26]->list;
  // self
  nodes[26]->list.blink = &nodes[26]->list;
  nodes[27]->list.blink = &nodes[29]->list;
  nodes[29]->list.flink = &nodes[7]->list;
  nodes[29]->list.blink = &nodes[30]->list;
  nodes[30]->list.blink = &nodes[31]->list;
  nodes[31]->list.blink = &nodes[24]->list;

  printf("o: rootA %p\n", nodes[0]);
  printf("o: rootB %p\n", nodes[7]);
  printf("o: rootC %p\n", nodes[22]);

  return 0;
}


int main(){


  test1();
  test_double_iter();

  printf("pid %u\n",getpid());
  fflush(stdout);
  sleep(-1);

  return 0;
}



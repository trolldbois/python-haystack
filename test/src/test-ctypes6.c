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

typedef struct slist SList;

struct slist {
  SList * next;
};

struct single_node
{
  unsigned int val1;
  SList entry;
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

struct Root
{
  unsigned int val1;
  struct Node * ptr_to_double_list;
  struct single_node * ptr_to_single_node;
  unsigned int val2;
};


void test_pointer_to_list(){
  // test with pointer in root node to test api
  struct Node * root_node, *node1, *node2;
  root_node = (struct Node *) malloc(sizeof(struct Node));
  node1 = (struct Node *) malloc(sizeof(struct Node));
  node2 = (struct Node *) malloc(sizeof(struct Node));
  root_node->val1 = 0xbbbbbbbb;
  root_node->val2 = 0xbbbbbbbb;
  node1->val1 = 0xbbbbbbbb;
  node1->val2 = 0xbbbbbbbb;
  node2->val1 = 0xbbbbbbbb;
  node2->val2 = 0xbbbbbbbb;
  node1->list.flink = &node2->list;
  node1->list.blink = (struct entry *) 0;
  node2->list.flink = (struct entry *) 0;
  node2->list.blink = &node1->list;
  root_node->list.flink = &node1->list;
  root_node->list.blink = &node2->list;
  // root_node is our double list

  struct single_node * single_node, *snode1, *snode2;
  single_node = (struct single_node *) malloc(sizeof(struct single_node));
  snode1 = (struct single_node *) malloc(sizeof(struct single_node));
  snode2 = (struct single_node *) malloc(sizeof(struct single_node));
  single_node->val1 = 0xbbbbbbb0;
  snode1->val1 = 0xbbbbbbb1;
  snode2->val1 = 0xbbbbbbb2;
  single_node->entry.next = &snode1->entry;
  snode1->entry.next = &snode2->entry;
  snode2->entry.next = (struct slist *) 0;
  // single_node is our single list

  struct Root * root;
  root = (struct Root *) malloc(sizeof(struct Root));
  root->val1 = 0xbbbbbbbf;
  root->val1 = 0xfffffffb;
  root->ptr_to_double_list = root_node;
  root->ptr_to_single_node = single_node;

  printf("o: test_pointer_to_list %p\n", root);

  return;
}

void test1(){
  // test Head-> node1 <-> node2
  struct usual * usual;
  usual = (struct usual *) malloc(sizeof(struct usual));
  strcpy(usual->txt, "This a string with a test this is a test string");
  usual->val1 = 0x0aaaaaaa;
  usual->val2 = 0x0ffffff0;
  //
  struct Node * node1, * node2;
  node1 = (struct Node *) malloc(sizeof(struct Node));
  node1->val1 = 0xdeadbeef;
  node1->val2 = 0xffffffff;
  node2 = (struct Node *) malloc(sizeof(struct Node));
  node2->val1 = 0xdeadbabe;
  node2->val2 = 0xffffffff;
  //
  node1->list.flink = &node2->list;
  node1->list.blink = (struct entry *) 0;
  //
  node2->list.flink = (struct entry *) 0;
  node2->list.blink = &node1->list;
  //
  usual->root.flink = &node1->list;
  usual->root.blink = &node1->list;
  //
  printf("o: test1 %p\n", usual);
  printf("o: test2 %p\n", node1);
  printf("o: test3 %p\n", node2);
  printf("rs: test1 %zu\n", sizeof(struct usual));
  printf("rs: test2 %zu\n", sizeof(struct Node));
  printf("rs: test3 %zu\n", sizeof(struct Node));
  return;
}

void test_double_iter(){
  // test node1 <-> node2 <-> ... <-> node255
  struct Node * nodes[255];
  for (int i=0;i<255;i++){
    nodes[i] = (struct Node *) malloc(sizeof(struct Node));
    nodes[i]->val1 = i;
    nodes[i]->val2 = i;
    nodes[i]->list.flink = 0x0;
    nodes[i]->list.blink = 0x0;
  }
  // we do a easy list
  for (int i=1;i<254;i++){
    nodes[i]->list.flink = &nodes[i+1]->list;
    nodes[i]->list.blink = &nodes[i-1]->list;
  }
  nodes[0]->list.flink = &nodes[1]->list;
  nodes[0]->list.blink = 0x0;
  nodes[254]->list.flink = 0x0;
  nodes[254]->list.blink = &nodes[253]->list;
  //
  printf("o: start_list %p\n", nodes[0]);
  printf("o: mid_list %p\n", nodes[127]);
  printf("o: end_list %p\n", nodes[254]);
  printf("rs: start_list %zu\n", sizeof(struct Node));
  printf("rs: end_list %zu\n", sizeof(struct Node));
  return;
};

void test_double_iter_with_head(){
  // test head -> node1 <-> node2 <-> ... <-> node16
  struct usual * head;
  struct Node * nodes[16];
  // head
  head = (struct usual *) malloc(sizeof(struct usual));
  head->val1 = 0xabababab;
  head->val2 = 0xdddddddd;
  // nodes
  for (int i=0;i<16;i++){
    nodes[i] = (struct Node *) malloc(sizeof(struct Node));
    nodes[i]->val1 = i;
    nodes[i]->val2 = i;
    nodes[i]->list.flink = 0x0;
    nodes[i]->list.blink = 0x0;
  }
  // we do a easy list
  for (int i=1;i<16;i++){
    nodes[i]->list.flink = &nodes[i+1]->list;
    nodes[i]->list.blink = &nodes[i-1]->list;
  }
  nodes[0]->list.flink = &nodes[1]->list;
  nodes[0]->list.blink = &head->root; // head sentinel
  nodes[15]->list.flink = 0x0; // null sentinel
  nodes[15]->list.blink = &nodes[14]->list;
  // head finish
  head->root.flink = &nodes[0]->list;
  head->root.blink = &head->root; // &nodes[15]->list;
  //
  printf("o: head_start_list %p\n", head);
  printf("o: head_first_item %p\n", nodes[0]);
  printf("o: head_last_item %p\n", nodes[15]);
  printf("rs: head_start_list %zu\n", sizeof(struct usual));
  printf("rs: head_first_item %zu\n", sizeof(struct Node));
  printf("rs: head_last_item %zu\n", sizeof(struct Node));
  return;
};

void test_double_iter_loop_with_head(){
  // test head <-> node1 <-> node2 <-> ... <-> node16 <-> head <-> node1 <-> ....
  struct usual * head;
  struct Node * nodes[16];
  // head
  head = (struct usual *) malloc(sizeof(struct usual));
  head->val1 = 0xabababab;
  head->val2 = 0xdddddddd;
  // nodes
  for (int i=0;i<16;i++){
    nodes[i] = (struct Node *) malloc(sizeof(struct Node));
    nodes[i]->val1 = i;
    nodes[i]->val2 = i;
    nodes[i]->list.flink = 0x0;
    nodes[i]->list.blink = 0x0;
  }
  // we do a easy list
  for (int i=1;i<16;i++){
    nodes[i]->list.flink = &nodes[i+1]->list;
    nodes[i]->list.blink = &nodes[i-1]->list;
  }
  nodes[0]->list.flink = &nodes[1]->list;
  nodes[0]->list.blink = &head->root; // head sentinel
  nodes[15]->list.flink = &head->root; // head sentinel
  nodes[15]->list.blink = &nodes[14]->list;
  // head finish
  head->root.flink = &nodes[0]->list;
  head->root.blink = &nodes[15]->list;
  //
  printf("o: head_loop_start_list %p\n", head);
  printf("o: head_loop_first_item %p\n", nodes[0]);
  printf("o: head_loop_last_item %p\n", nodes[15]);
  printf("rs: head_loop_start_list %zu\n", sizeof(struct usual));
  printf("rs: head_loop_first_item %zu\n", sizeof(struct Node));
  printf("rs: head_loop_last_item %zu\n", sizeof(struct Node));
  return;
};

void test_double_iter_loop_with_head_insertion(){
  // test head -> node1 <-> node2 <-> ... <-> node16 <-> node1 <-> node2 ...
  struct usual * head;
  struct Node * nodes[16];

  head = (struct usual *) malloc(sizeof(struct usual));

  for (int i=0;i<16;i++){
    nodes[i] = (struct Node *) malloc(sizeof(struct Node));
    nodes[i]->val1 = i;
    nodes[i]->val2 = i;
    nodes[i]->list.flink = 0x0;
    nodes[i]->list.blink = 0x0;
  }
  // we do a easy list
  for (int i=1;i<16;i++){
    nodes[i]->list.flink = &nodes[i+1]->list;
    nodes[i]->list.blink = &nodes[i-1]->list;
  }
  // create a loop
  nodes[0]->list.flink = &nodes[1]->list;
  nodes[0]->list.blink = &nodes[15]->list;
  nodes[15]->list.flink = &nodes[0]->list;
  nodes[15]->list.blink = &nodes[14]->list;
  //
  printf("o: loop_head_insert %p\n", head);
  printf("o: loop_first_item %p\n", nodes[0]);
  printf("o: loop_last_item %p\n", nodes[15]);
  printf("rs: loop_head_insert %zu\n", sizeof(struct usual));
  printf("rs: loop_first_item %zu\n", sizeof(struct Node));
  printf("rs: loop_last_item %zu\n", sizeof(struct Node));
  return;
};

void test_double_graph_iter(){
  // test graph.
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

  return;
}


int main(){


  test1(); // 3 mallocs
  test_double_iter(); // 255 mallocs
  test_double_iter_with_head(); // 17 mallocs
  test_double_iter_loop_with_head(); // 17 mallocs
  test_double_iter_loop_with_head_insertion(); // 17 mallocs
  test_double_graph_iter(); // 32 mallocs
  test_pointer_to_list(); // 7 mallocs

  printf("pid %u\n",getpid());
  fflush(stdout);
  sleep(-1);

  return 0;
}



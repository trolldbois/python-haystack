
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifdef PYTHON_BUILD
#endif

// structs
struct sA {
  int a;
};

struct sB : sA {
  unsigned int b;
};

struct sC : sB {
  private:
  unsigned int c;
};

struct sD : sB {
  public:
  unsigned int d;
};

// classes
class cA {
  int a;
};

class cB : cA {
  unsigned int b;
};

class cC : cB {
  private:
  unsigned int c;
};

class cD : cB {
  public:
  unsigned int d;
};

class cE : cD, cC {
  public:
  unsigned int e;
};


int test_classes()
{
  std::cout << " -- classes --" << std::endl;

  cA * a = new cA();
  cB * b = new cB();
  cC * c = new cC();
  cD * d = new cD();
  cE * e = new cE();
  
  printf(" a is at 0x%x , size: %d \n", (unsigned int) a, sizeof(cA));
  printf(" b is at 0x%x , size: %d \n", (unsigned int) b, sizeof(cB));
  printf(" c is at 0x%x , size: %d \n", (unsigned int) c, sizeof(cC));
  printf(" d is at 0x%x , size: %d \n", (unsigned int) d, sizeof(cD));
  printf(" e is at 0x%x , size: %d \n", (unsigned int) e, sizeof(cE));

  std::cout << " -- end classes --" << std::endl;
  
  return 0;
}

int test_structs()
{
  sA * a = (sA * ) malloc(sizeof(sA));
  sB * b = (sB * ) malloc(sizeof(sB));
  sC * c = (sC * ) malloc(sizeof(sC));
  sD * d = (sD * ) malloc(sizeof(sD));
}

int main(){
  
  test_structs();
  test_classes();
  return 0;
}

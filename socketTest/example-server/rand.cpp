#include <iostream>
#include <stdlib.h>
#include <time.h>

using namespace std;

int main(){

srand(17135);

for(int i = 0;i < 10; i++)
	cout << rand() << '\t';

return 0;

}

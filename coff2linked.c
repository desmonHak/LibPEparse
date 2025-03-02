#include <stdio.h>

// External declaration of the add function
extern int add(int n1, int n2);

int main() {
    int result = add(5, 3);
    printf("Result of add(5, 3): %d\n", result);
    return 0;
}

#include <stdio.h>
#include <stdint.h>

void target_function() {
    printf("Reached Target!\n");
}

void analyze_input(uint32_t input) {
    if (input > 100 && input <= 200) {
        target_function();
    }
}

int main() {
    uint32_t user_input;
    printf("Enter number: ");
    scanf("%u", &user_input);
    analyze_input(user_input);
    return 0;
}

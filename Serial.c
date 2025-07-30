#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <omp.h>


char target_hash[] = "24f916304a3a9fc2213185a5bce0c723813a6425bb26958647059b208f3f5420"; // find the password
const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; // Character set
const int charset_len = 62;

// Hash Function: Takes a password, calculates its SHA-256 hash, stores it
void sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

// Converts a number (like 12345) into a password (like "abc")
void index_to_password(long long index, int length, char *password) {
    for (int i = length - 1; i >= 0; i--) {
        password[i] = charset[index % charset_len];
        index /= charset_len;
    }
    password[length] = '\0';
}

int main() {
    char password[11];
    char hash_out[65];
    int found = 0; //flag
    double total_start = omp_get_wtime(); //get wall time start


    for (int length = 0; length <= 10; length++) {
        long long combinations = 1;
        for (int i = 0; i < length; i++) combinations *= charset_len; //COMBINATIONS of 62*LENGTH

        printf("Trying length %d: %lld combinations\n", length, combinations);

        double start_time = omp_get_wtime();

        for (long long i = 0; i < combinations; i++) {
            if (found) break;

            index_to_password(i, length, password); //convert number to password
            sha256(password, hash_out); // get hash of that password

            if (strcmp(hash_out, target_hash) == 0) {
                printf("Password found: %s\n", password);
                found = 1;
                break;
            }
        }

        double end_time = omp_get_wtime();
        double time_taken = (end_time - start_time);  // Time taken for this length
        printf("Time taken for length %d: %f seconds\n", length, time_taken);

        if (found) break;
        printf("--------------------------------------------------------------\n");

    }
    double total_end = omp_get_wtime();  // Total time end
    double total_time_taken = total_end - total_start;  // Total time taken
    printf("Total time taken: %f seconds\n", total_time_taken);

    return 0;
}





//gcc Serial.c -o Serial -lcrypto -fopenmp

//gcc Serial.c -o Serial -lcrypto
//./Serial
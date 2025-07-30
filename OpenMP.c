
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <omp.h>

char target_hash[] = "24f916304a3a9fc2213185a5bce0c723813a6425bb26958647059b208f3f5420"; //find a password
const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; //Character set
const int charset_len = 62;

//Hash FUnction ,Takes a password, calculates its SHA-256 hash, and stores it
void sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
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
    int found = 0;
    double total_start = omp_get_wtime();  // Total time start

    //For each length, calculates how many possible combinations exist
    for (int length = 0; length <= 6; length++) {
        long long combinations = 1;
        for (int i = 0; i < length; i++) combinations *= charset_len;
        

        printf("Trying length %d: %lld combinations\n", length, combinations);

        double start_time = omp_get_wtime(); 
        //Uses multiple CPU cores (with OpenMP) to check combinations faster
        #pragma omp parallel for private(password, hash_out) shared(found) 
        for (long long i = 0; i < combinations; i++) {
            if (found) continue;

            index_to_password(i, length, password);
            sha256(password, hash_out);

            if (strcmp(hash_out, target_hash) == 0) {
                #pragma omp critical
                {
                    printf("Password found: %s\n", password);
                    found = 1;
                }
            }
        }

        double end_time = omp_get_wtime(); 
        double time_taken = (end_time - start_time); 
        printf("Time taken for length %d: %f seconds\n", length, time_taken); 

        if (found) break;
        printf("--------------------------------------------------------------\n");
    }

    double total_end = omp_get_wtime();  // Total time end
    double total_time_taken = total_end - total_start;  // Total time taken
    printf("Total time taken: %f seconds\n", total_time_taken);

    return 0;
}


//gcc -fopenmp OpenMP.c -lcrypto -o OpenMP
// ./OpenMP
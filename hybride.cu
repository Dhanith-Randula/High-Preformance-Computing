#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>

#define MAX_LEN 6
#define CHARSET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define CHARSET_LEN 62
#include <omp.h>
int found_length = 0;
char found_result[MAX_LEN + 1] = {0};
bool found = false;

// GPU constants
__device__ __constant__ char d_charset[CHARSET_LEN];
__device__ __constant__ char d_target_hash[65];
__device__ volatile unsigned int d_found = 0;
__device__ char d_result[MAX_LEN + 1];

// Converts an index into a password string
__device__ void index_to_password(unsigned long long idx, int length, char *out) {
    for (int i = length - 1; i >= 0; i--) {
        out[i] = d_charset[idx % CHARSET_LEN];
        idx /= CHARSET_LEN;
    }
    out[length] = '\0';
}

// Compare two hex hashes
__device__ bool match_hash(const char *h1, const char *h2) {
    for (int i = 0; i < 64; i++) {
        if (h1[i] != h2[i]) return false;
    }
    return true;
}

// SHA-256 constants
__device__ __constant__ unsigned int k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 helper functions
__device__ inline unsigned int rotr(unsigned int x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}
__device__ inline unsigned int Ch(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}
__device__ inline unsigned int Maj(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
__device__ inline unsigned int Sigma0(unsigned int x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
__device__ inline unsigned int Sigma1(unsigned int x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
__device__ inline unsigned int sigma0(unsigned int x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
__device__ inline unsigned int sigma1(unsigned int x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256 padding and message schedule
__device__ void sha256_pad(const char *input, int len, unsigned int *w) {
    for (int i = 0; i < 16; i++) w[i] = 0;
    for (int i = 0; i < len; i++) {
        w[i >> 2] |= ((unsigned int)input[i]) << (24 - (8 * (i & 3)));
    }
    w[len >> 2] |= 0x80 << (24 - (8 * (len & 3)));
    unsigned long long bit_len = (unsigned long long)len * 8;
    w[15] = (unsigned int)(bit_len);
    w[14] = (unsigned int)(bit_len >> 32);
}

// Computes SHA-256 hash of a string
__device__ void sha256(const char *input, int len, char *output) {
    unsigned int h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    unsigned int w[64];
    sha256_pad(input, len, w);

    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    unsigned int a = h[0], b = h[1], c = h[2], d = h[3];
    unsigned int e = h[4], f = h[5], g = h[6], h_var = h[7];

    for (int i = 0; i < 64; i++) {
        unsigned int T1 = h_var + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
        unsigned int T2 = Sigma0(a) + Maj(a, b, c);
        h_var = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned char byte = (h[i] >> (24 - j * 8)) & 0xFF;
            output[i * 8 + j * 2] = (byte >> 4) < 10 ? '0' + (byte >> 4) : 'a' + (byte >> 4) - 10;
            output[i * 8 + j * 2 + 1] = (byte & 0xF) < 10 ? '0' + (byte & 0xF) : 'a' + (byte & 0xF) - 10;
        }
    }
    output[64] = '\0';
}

// Kernel to crack passwords
__global__ void crack_password(int length, unsigned long long start_idx, unsigned long long end_idx) {
    unsigned long long idx = start_idx + blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= end_idx || d_found) return;

    char candidate[MAX_LEN + 1];
    char hash_out[65];

    index_to_password(idx, length, candidate);
    sha256(candidate, length, hash_out);

    if (match_hash(hash_out, d_target_hash)) {
        unsigned int expected = 0;
        if (atomicCAS((unsigned int*)&d_found, expected, 1) == 0) {
            for (int i = 0; i < length; i++) {
                d_result[i] = candidate[i];
            }
            d_result[length] = '\0';
        }
    }
}

int main() {
    const char target_hash[65] = "24f916304a3a9fc2213185a5bce0c723813a6425bb26958647059b208f3f5420";
    
    // Copy constant data to GPU once
    cudaMemcpyToSymbol(d_charset, CHARSET, CHARSET_LEN);
    cudaMemcpyToSymbol(d_target_hash, target_hash, 65);

    printf("Target hash: %s\n", target_hash);
    printf("Searching passwords length 1 to %d...\n", MAX_LEN);

    double total_start = omp_get_wtime();  // Total time start

    #pragma omp parallel for schedule(dynamic) // according to load divide to threads
    for (int length = 1; length <= MAX_LEN; length++) {
        if (found) continue;  // Early exit if already found
        // Calculate combinations for this length
        unsigned long long combinations = 1;
        for (int i = 0; i < length; i++) combinations *= CHARSET_LEN;
        
        printf("\nTrying length %d: %llu combinations\n", length, combinations);

        // Reset found flag
        unsigned int h_found = 0;
        cudaMemcpyToSymbol(d_found, &h_found, sizeof(unsigned int));

        // Setup timing
        cudaEvent_t start, stop;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start);

        // Configure kernel launch
        int threads_per_block = 256;
        unsigned long long max_blocks = 65535;
        unsigned long long chunk_size = threads_per_block * max_blocks;
        unsigned long long chunks = (combinations + chunk_size - 1) / chunk_size;

        for (unsigned long long chunk = 0; chunk < chunks && !h_found; chunk++) {
            unsigned long long start_idx = chunk * chunk_size;
            unsigned long long end_idx = (chunk + 1) * chunk_size;
            if (end_idx > combinations) end_idx = combinations;
            
            int blocks = (end_idx - start_idx + threads_per_block - 1) / threads_per_block;
            crack_password<<<blocks, threads_per_block>>>(length, start_idx, end_idx);
            
            cudaDeviceSynchronize();  // Ensure GPU work is done before checking flag
            cudaMemcpyFromSymbol(&h_found, d_found, sizeof(unsigned int));
        }

        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        float milliseconds = 0;
        cudaEventElapsedTime(&milliseconds, start, stop);
        cudaEventDestroy(start);
        cudaEventDestroy(stop);

        printf("Length %d: Time taken = %.3f seconds\n", length, milliseconds / 1000.0f);

       
        

        if (h_found) {
        #pragma omp critical
        {
            if (!found) {
                cudaMemcpyFromSymbol(found_result, d_result, length + 1);
                found = true;
                found_length = length;
            }
        }
    }
    }

    if (found) {
            printf("\nPASSWORD FOUND: %s\n", found_result);
            double total_end = omp_get_wtime();
            printf("\nTotal Time Taken: %.3f seconds\n", total_end - total_start);

        }
    else {
        printf("\nPassword not found in lengths 1-%d\n", MAX_LEN);
        double total_end = omp_get_wtime();
        printf("\nTotal Time Taken: %.3f seconds\n", total_end - total_start);
    }
}


//nvcc CUDACrack.cu -o CUDACrack.o
// nvcc -arch=sm_75 -Xcompiler -fopenmp hybride.cu -o hybrid.o

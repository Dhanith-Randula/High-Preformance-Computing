# 🔐 CUDA + OpenMP SHA-256 Password Cracker

This project is a high-performance brute-force password cracker that matches a given SHA-256 hash by generating and hashing possible password combinations.

It supports both:
- **Parallel CPU execution using OpenMP**
- **Massively parallel GPU execution using CUDA**

---

## 🚀 Features

- Brute-force all combinations of characters up to a defined max length
- Supports alphanumeric charset: `0-9`, `A-Z`, `a-z`
- SHA-256 hash comparison
- Early exit when password is found
- CPU version with OpenMP for multi-core performance
- GPU version using CUDA for massive parallelism

---

## 🧠 How It Works

1. A SHA-256 hash is provided as the target.
2. The program generates every possible string (password) of lengths 1 to `MAX_LEN` using the given character set.
3. For each password:
   - It calculates the SHA-256 hash.
   - Compares it with the target hash.
   - If matched, the password is printed and execution stops.

OpenMP and CUDA are used to divide the work and significantly speed up execution.

---

## 📁 File Structure

```bash
.
├── Serial.c              # Serial version 
├── OpenMP.c              # CPU version with OpenMP
├── CUDACrack.cu          # GPU version with CUDA
├── Hybride.cu          # GPU + CPU version 
├── README.md             # This file

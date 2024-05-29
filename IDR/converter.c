#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Function to convert a hexadecimal string to a byte array
void hexStringToByteArray(const char* hexString, unsigned char* byteArray, size_t byteArraySize) {
    for (size_t i = 0; i < byteArraySize; i++) {
        sscanf_s(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

// Function to convert a byte array to a hexadecimal string
void byteArrayToHexString(const unsigned char* byteArray, char* hexString, size_t byteArraySize) {
    for (size_t i = 0; i < byteArraySize; i++) {
        sprintf_s(hexString + 2 * i, 3, "%02x", byteArray[i]);
    }
}

// Function to XOR array1 with array2, repeating array2 as needed
void xorByteArrays(const unsigned char* array1, const unsigned char* array2, unsigned char* result, size_t size1, size_t size2) {
    for (size_t i = 0; i < size1; i++) {
        result[i] = array1[i] ^ array2[i % size2];
    }
}

VOID convert(const char* hexString, const char* key[], unsigned char* result) {
    // Calculate the length of the byte arrays
    size_t byteArraySize = strlen(hexString) / 2;

    // Allocate memory for the byte arrays and result
    unsigned char* byteArray = (unsigned char*)malloc(byteArraySize);
    if (byteArray == NULL) {
        return 1;
    }

    // Convert hexadecimal strings to byte arrays
    hexStringToByteArray(hexString, byteArray, byteArraySize);

    // XOR the byte arrays, repeating array2 as needed
    xorByteArrays(byteArray, key, result, byteArraySize, strlen(key));

    free(byteArray);
    //free(byteArray2);
}
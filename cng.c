#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define ADD_EXPORTS
#define IMECLUI_IMPLEMENTATION
#include "src/imeclui.h"

#define ARGPARSE_IMPLEMENTATION
#include "src/argparse.h"


#ifdef _LINUX
#include "kcapi.h"
#endif // _LINUX

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif // _WIN32

// ===--- MACROS ---============================================================
#define __MACROS

// Colors
#define C_RESET \
    IME_ESC     \
    IME_RESET   \
    IME_ESC_END
#define C_RED \
    IME_ESC   \
    IME_RED   \
    IME_ESC_END
#define C_GREEN \
    IME_ESC     \
    IME_GREEN   \
    IME_ESC_END
#define C_CYAN                 \
    IME_ESC                    \
    IME_RGB_COLOR(0, 200, 180) \
    IME_ESC_END
#define C_DIMM       \
    IME_ESC          \
    IME_BRIGHT_BLACK \
    IME_ESC_END

#define C_HEADER                \
    IME_ESC                     \
    IME_RGB_COLOR(255, 117, 24) \
    IME_ESC_END

#define C_ERROR \
    C_RED

// Main assert, in a 'slay💅' style
#define MASSERT(cond, msg)                                              \
    if (!(cond))                                                        \
    {                                                                   \
        printf(C_ERROR);                                                \
        printf("[ASSERTION FAILED] (%lld) <%s:%d:%s> %s\n",             \
               (long long)(cond), __FILE__, __LINE__, __func__, msg);   \
        printf(C_RESET " ");                                            \
        exit(1);                                                        \
    }

// Preferrable allocators
#define ALLOC(T, size) ((T *)malloc((size) * sizeof(T)))
#define CALLOC(T, size) ((T *)calloc((size), sizeof(T)))
#define REALLOC(T, ptr, size) ((T *)realloc(ptr, (size) * sizeof(T)))
#define FREE(ptr)    \
    if (ptr != NULL) \
    {                \
        free(ptr);   \
        ptr = NULL;  \
    }



// int main(int argc, char *argv[])
// {
//     char buf[8192];
//     struct kcapi_handle *handle;
//     struct iovec iov;
//     ssize_t ret;
//     int i;

//     (void)argc;
//     (void)argv;

//     iov.iov_base = buf;

//     ret = kcapi_cipher_init(&handle, "cbc(aes)", 0);
//     if (ret)
//             return (int)ret;

//     ret = kcapi_cipher_setkey(handle, (unsigned char *)"0123456789abcdef", 16);
//     if (ret)
//             return (int)ret;

//     ret = kcapi_cipher_stream_init_enc(handle, (unsigned char *)"0123456789abcdef", NULL, 0);
//     if (ret < 0)
//             return (int)ret;

// 	for (i = 0; i < 100; i++) {
// 		//printf("round %d\n", i);

// 		iov.iov_len = 6182;
// 		ret = kcapi_cipher_stream_update(handle, &iov, 1);
// 		if (ret < 0)
// 			return (int)ret;

// 		iov.iov_len = 6182;
// 		ret = kcapi_cipher_stream_op(handle, &iov, 1);
// 		if (ret < 0)
// 			return (int)ret;
// 	}

//         kcapi_cipher_destroy(handle);

//         return 0;
// }

/// @brief Write byte array to a binary file
/// @param bytes
/// @param size
/// @param file_name
void fwrite_bin(const uint8_t *bytes, size_t size, const char *file_name)
{
    FILE *file = fopen(file_name, "wb");
    MASSERT(file != NULL, "Can't open file for writing");
    fwrite(bytes, 1, size, file);
    fclose(file);
}

/// @brief Read binary file to a byte array
/// @param bytes pointer to the result
/// @param size pointer to the result
/// @param file_name
/// @warning The result must be freed after usage
void fread_bin(uint8_t **bytes, size_t *size, const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file for reading");
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *bytes = ALLOC(uint8_t, *size);
    MASSERT(*bytes != NULL, "Memory allocation failed");
    fread(*bytes, 1, *size, file);
    fclose(file);
}

/// @brief Print byte as binary number
/// @param byte
void print_byte_bin(uint8_t byte)
{
    int i;
    for (i = 0; i < 8; i++)
    {
        uint8_t shift_byte = 0x01 << (7 - i);
        if (shift_byte & byte)
        {
            printf("1");
        }
        else
        {
            printf("0");
        }
    }
}

/// @brief Convert array of integers to a null-terminated
/// string of ASCII characters
/// @param data array of integers
/// @param data_size
/// @param str pointer to the result
/// @warning The result must be freed after usage
void convert_array_to_str(unsigned long long int *data, size_t data_size, char **str)
{
    char *res = CALLOC(char, data_size);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = (char)data[i];
    }
    *str = res;
}

/// @brief Read chunk of data from file
/// @param bytes pointer to the result
/// @param size pointer to the result
/// @param start start position in file
/// @param end end position in file
/// @param file_name
/// @warning The result must be freed after usage
void read_bin_file_chunk(uint8_t **bytes, size_t *size,
                         size_t start, size_t end,
                         const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (end == 0)
    {
        end = file_size;
    }
    if (end > file_size)
    {
        end = file_size;
    }
    *size = end - start;
    *bytes = ALLOC(uint8_t, *size);
    MASSERT(*bytes != NULL, "Memory allocation failed");
    fseek(file, start, SEEK_SET);
    fread(*bytes, 1, *size, file);
    fclose(file);
}

/// @brief Write chunk of data to a specified position in file
/// @param bytes data to write
/// @param size data size
/// @param start start position in file
/// @param file_name file name
void write_bin_file_chunk(const uint8_t *bytes, size_t size,
                          size_t start, const char *file_name)
{
    FILE *file = fopen(file_name, "r+b");
    if (file == NULL)
    {
        file = fopen(file_name, "wb");
    }
    MASSERT(file != NULL, "Can't open file");
    fseek(file, start, SEEK_SET);
    fwrite(bytes, 1, size, file);
    fclose(file);
}

/// @brief Count chunks in the file
/// @param file_name
/// @param chunk_size
/// @return number of chunks in the file
size_t count_file_chunks(const char *file_name, size_t chunk_size)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return (file_size + chunk_size - 1) / chunk_size;
}

/// @brief Get file size
/// @param file_name
/// @return file size in bytes
size_t file_size(const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return file_size;
}

/// @brief Print byte array as hex string
/// @param array [in] byte array
/// @param size [in] array size
void print_byte_array_hex(uint8_t *array, size_t size) {
    printf("0x");
    for (size_t i = 0; i < size; i++) {
        printf("%02X", array[i]);
    }
    printf("\n");
}


#ifdef _LINUX
int test_sym_aes(){
    char buf[8192];
    struct kcapi_handle *handle;

    // Initialization vector 
    struct iovec iov;
    int i;


    iov.iov_base = buf;

    // struct kcapi_handle *handle = NULL;
    const char *key = "0123456789abcdef"; // 16 bytes key for AES-128
    const char *iv = "abcdef9876543210";  // 16 bytes IV for AES-CBC
    char *plaintext_orig = "This is a test message... cat cat";
    unsigned char ciphertext[128]; // Ensure this is large enough for your data
    int ret;

    char *plaintext = ALLOC(char, strlen(plaintext_orig) + 1 + 100);
    strcpy(plaintext, plaintext_orig);
    char *text_out = CALLOC(char, strlen(plaintext_orig) + 1 + 100);

    printf("Plaintext: %s\n", plaintext);
    
    // Initialize the cipher handle
    // char *alg = "cbc(aes)";
    char *alg = "ecb(aes)";
    ret = kcapi_cipher_init(&handle, alg, 0);
    if (ret) {
        fprintf(stderr, "kcapi_cipher_init() failed: %d\n", ret);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return ret;
    }
    printf("Handle: 0x%016llX\n", (long long unsigned int)handle);
    printf("Using: %s\n", alg);
    
    // Set the encryption key
    ret = kcapi_cipher_setkey(handle, (const uint8_t*)key, strlen(key));
    if (ret) {
        fprintf(stderr, "kcapi_cipher_setkey() failed: %d\n", ret);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        kcapi_cipher_destroy(handle);
        return ret;
    }
    
    // Encrypt the data
    ret = kcapi_cipher_stream_init_enc(handle, (const uint8_t*)iv, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "kcapi_cipher_stream_init_enc() failed: %d\n", ret);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        kcapi_cipher_destroy(handle);
        return ret;
    }

    for (i = 0; i < strlen(plaintext); i++) {
        iov.iov_len = 1;
        iov.iov_base = (void *)plaintext + i;
        ret = kcapi_cipher_stream_update(handle, &iov, 1);
        if (ret < 0) {
            fprintf(stderr, "kcapi_cipher_stream_update() failed: %d\n", ret);
            fprintf(stderr, "Error: %s\n", strerror(errno));
            kcapi_cipher_destroy(handle);
            return ret;
        }
        ciphertext[i] = ((char *)iov.iov_base)[0];
    }

    printf("Encoded: ");
    for (int i = 0; i < strlen(plaintext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // prepare to decode data
    ret = kcapi_cipher_stream_init_dec(handle, (const uint8_t*)iv, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "kcapi_cipher_stream_init_dec() failed: %d\n", ret);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        kcapi_cipher_destroy(handle);
        return ret;
    }

    // Decode the data
    for (i = 0; i < strlen(plaintext); i++) {
        iov.iov_len = 1;
        iov.iov_base = (void *)ciphertext + i;
        ret = kcapi_cipher_stream_update(handle, &iov, 1);
        if (ret < 0) {
            fprintf(stderr, "kcapi_cipher_stream_update() failed: %d\n", ret);
            fprintf(stderr, "Error: %s\n", strerror(errno));
            kcapi_cipher_destroy(handle);
            return ret;
        }
        text_out[i] = ((char *)iov.iov_base)[0];
    }

    printf("Decoded: %s\n", text_out);

    printf("Encryption successful. Ciphertext length: %d\n", ret);
    

    // Clean up
    FREE(text_out);
    FREE(plaintext)
    kcapi_cipher_destroy(handle);
    return 0;
}

void generate_key(const char *key_path)
{
    uint8_t key[16];
    FILE *file = fopen(key_path, "wb");
    MASSERT(file != NULL, "Can't open file for writing");
    for (int i = 0; i < 16; i++)
    {
        key[i] = rand() % 256;
    }
    fwrite(key, 1, 16, file);
    fclose(file);
}

uint8_t* kpp_keygen(const char *ciphername)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	size_t outbuflen;
	ssize_t ret;


    ret = kcapi_kpp_init(&handle, "ctr(aes)", 0);
    fprintf(stderr, "kcapi_kpp_init() failed: %d\n", ret); 
    fprintf(stderr, "Error: %s\n", strerror(errno));
    MASSERT(ret >= 0, "Initialization of cipher failed");

	// ret = kcapi_kpp_setkey(handle, cavs_test->key, cavs_test->keylen);
    // MASSERT(ret >= 0, "Having kernel generating keys failed\n");

	outbuflen = 128;
	{
		outbuf = CALLOC(uint8_t, (size_t)ret);
        MASSERT(outbuf != NULL, "Memory allocation failed");
	}

    ret = kcapi_kpp_keygen(handle, outbuf, outbuflen, KCAPI_ACCESS_SENDMSG);
    MASSERT(ret >= 0, "Key generation failed");

	kcapi_kpp_destroy(handle);

    // kcapi_aes_
    return outbuf;
}
#endif // _LINUX

#ifdef _WIN32

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define AES_KEY_SIZE 16 // 128 bits
#define CHUNK_SIZE 4096

/// @brief Generate AES key and save it to a file
/// @param key_path [in] path to the key file
void win_generate_aes_key(char *key_path) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD keyObjectLength = 0, resultLength = 0;
    PBYTE keyObject = NULL;
    PBYTE keyBlob = NULL;
    PBYTE keyMaterial = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, 
        BCRYPT_AES_ALGORITHM, NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Calculate the size of the buffer to hold the key object
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, 
        (PBYTE)&keyObjectLength, sizeof(DWORD), &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // Allocate the key object
    keyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObjectLength);
    MASSERT(keyObject != NULL, "HeapAlloc failed");

    // Allocate the key material
    keyMaterial = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_KEY_SIZE);
    MASSERT(keyMaterial != NULL, "HeapAlloc failed");

    // Generate random key material
    status = BCryptGenRandom(NULL, keyMaterial, AES_KEY_SIZE, 
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    MASSERT(NT_SUCCESS(status), "BCryptGenRandom failed");

    // Generate the key
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, keyObject, 
        keyObjectLength, keyMaterial, AES_KEY_SIZE, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGenerateSymmetricKey failed");

    // Get size of the key and allocate memory
    status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, 
        &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptExportKey failed");

    keyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, resultLength);
    MASSERT(keyBlob != NULL, "HeapAlloc failed");

    // Export the key
    // BCRYPT_KEY_DATA_BLOB - key material is exported in plaintext form
    // BCRYPT_OPAQUE_KEY_BLOB - key material is embedded in a BLOB that is 
    //      encrypted
    status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, keyBlob, 
        resultLength, &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptExportKey failed");

    // Save the key to a file or use it as needed
    FILE *keyFile = fopen(key_path, "wb");
    if (keyFile) {
        fwrite(keyBlob, 1, resultLength, keyFile);
        fclose(keyFile);
        printf("AES%d key generated and saved to '%s'\n", 
            AES_KEY_SIZE * 8, key_path);
    } else {
        printf("Failed to open file for writing\n");
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (keyObject) HeapFree(GetProcessHeap(), 0, keyObject);
    if (keyBlob) HeapFree(GetProcessHeap(), 0, keyBlob);
}

/// @brief Read AES key from file
/// @param key_path [in] path to the key file
/// @param keyBlob [out] pointer to the key
/// @param keySize [out] pointer to the key size
void win_read_aes_key(char *key_path, BYTE **keyBlob, DWORD *keySize) {
    FILE *keyFile = fopen(key_path, "rb");
    if (keyFile) {
        fseek(keyFile, 0, SEEK_END);
        *keySize = ftell(keyFile);
        fseek(keyFile, 0, SEEK_SET);
        // keyBlob = (BYTE *)HeapAlloc(GetProcessHeap(), 0, keySize);
        *keyBlob = ALLOC(BYTE, (size_t)*keySize);
        if (keyBlob) {
            fread(keyBlob, 1, (size_t)*keySize, keyFile);
            fclose(keyFile);
            printf("AES key read from file\n");
        } else {
            printf("Failed to allocate memory for key\n");
        }
    } else {
        printf("Failed to open file for reading\n");
    }
}

void win_generate_aes_iv(char *iv_path) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;
    DWORD ivSize = AES_KEY_SIZE; // AES block size is 16 bytes
    BYTE iv[AES_KEY_SIZE];
    FILE *ivFile = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, 
        BCRYPT_AES_ALGORITHM, NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Generate random IV
    status = BCryptGenRandom(NULL, iv, ivSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    MASSERT(NT_SUCCESS(status), "BCryptGenRandom failed");

    // Write IV to file
    ivFile = fopen(iv_path, "wb");
    MASSERT(ivFile != NULL, "Failed to open IV file for writing");
    fwrite(iv, 1, ivSize, ivFile);
    fclose(ivFile);

    // Clean up
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}

void win_read_aes_iv(char *iv_path, BYTE **ivBlob, DWORD *ivSize) {
    FILE *ivFile = fopen(iv_path, "rb");
    MASSERT(ivFile != NULL, "Failed to open IV file");

    fseek(ivFile, 0, SEEK_END);
    *ivSize = ftell(ivFile);
    fseek(ivFile, 0, SEEK_SET);

    *ivBlob = ALLOC(BYTE, *ivSize);
    MASSERT(*ivBlob != NULL, "Memory allocation failed");

    fread(*ivBlob, 1, *ivSize, ivFile);
    fclose(ivFile);
}

        // [in] путь к файлу ключа
        // [in] путь к файлу для шифрования
        // [in] режим сцепления блоков
        // [out] путь к инициализирующему вектору
        // [out] путь к зашифрованному файлу
void win_encrypt_chunk_aes(BYTE *chunk, DWORD chunk_size, 
    BYTE *keyBlob, DWORD keySize, BYTE *iv, DWORD ivSize,
    BYTE **ciphertext, DWORD *ciphertextSize) 
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD resultLength = 0;
    BYTE *keyObject = NULL;
    DWORD keyObjectSize = 0;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjectSize, sizeof(DWORD), &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // Allocate the key object
    keyObject = ALLOC(BYTE, keyObjectSize);
    MASSERT(keyObject != NULL, "HeapAlloc failed");

    // Generate the key from the keyBlob
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, keyBlob, keySize, 0);
    // printf("status: %ld\n", status);
    // status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, keyObject, keyObjectSize, keyBlob, keySize, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGenerateSymmetricKey failed");

    // Calculate the buffer size for the ciphertext
    status = BCryptEncrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, NULL, 0, ciphertextSize, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptEncrypt failed");

    // Allocate the ciphertext buffer
    *ciphertext = ALLOC(BYTE, *ciphertextSize);
    MASSERT(*ciphertext != NULL, "HeapAlloc failed");

    // Perform the encryption
    status = BCryptEncrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, *ciphertext, *ciphertextSize, &resultLength, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptEncrypt failed");

    // Clean up
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (keyObject) free(keyObject);
}

void win_encrypt_file_aes(char *key_path, char *file_path, 
    char *chaining, char *iv_path, char *output_path) 
{
    FILE *keyFile = fopen(key_path, "rb");
    FILE *ivFile = fopen(iv_path, "rb");
    FILE *inputFile = fopen(file_path, "rb");
    FILE *outputFile = fopen(output_path, "wb");
    MASSERT(keyFile != NULL, "Failed to open key file");
    MASSERT(ivFile != NULL, "Failed to open IV file");
    MASSERT(inputFile != NULL, "Failed to open input file");
    MASSERT(outputFile != NULL, "Failed to open output file");

    fseek(keyFile, 0, SEEK_END);
    DWORD keySize = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);
    BYTE *keyBlob = ALLOC(BYTE, keySize);
    fread(keyBlob, 1, keySize, keyFile);
    fclose(keyFile);

    fseek(ivFile, 0, SEEK_END);
    DWORD ivSize = ftell(ivFile);
    fseek(ivFile, 0, SEEK_SET);
    BYTE *iv = ALLOC(BYTE, ivSize);
    fread(iv, 1, ivSize, ivFile);
    fclose(ivFile);

    BYTE chunk[CHUNK_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(chunk, 1, CHUNK_SIZE, inputFile)) > 0) {
        BYTE *ciphertext = NULL;
        DWORD ciphertextSize = 0;
        win_encrypt_chunk_aes(chunk, bytesRead, keyBlob, keySize, iv, ivSize, &ciphertext, &ciphertextSize);
        fwrite(ciphertext, 1, ciphertextSize, outputFile);
        free(ciphertext);
    }

    fclose(inputFile);
    fclose(outputFile);
    free(keyBlob);
    free(iv);
}

void win_decrypt_chunk_aes(BYTE *chunk, DWORD chunk_size, 
    BYTE *keyBlob, DWORD keySize, BYTE *iv, DWORD ivSize,
    BYTE **plaintext, DWORD *plaintextSize) 
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD resultLength = 0;
    BYTE *keyObject = NULL;
    DWORD keyObjectSize = 0;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjectSize, sizeof(DWORD), &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // Allocate the key object
    keyObject = ALLOC(BYTE, keyObjectSize);
    MASSERT(keyObject != NULL, "HeapAlloc failed");

    // Generate the key from the keyBlob
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, keyObject, keyObjectSize, keyBlob, keySize, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGenerateSymmetricKey failed");

    // Calculate the buffer size for the plaintext
    status = BCryptDecrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, NULL, 0, plaintextSize, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptDecrypt failed");

    // Allocate the plaintext buffer
    *plaintext = ALLOC(BYTE, *plaintextSize);
    MASSERT(*plaintext != NULL, "HeapAlloc failed");

    // Perform the decryption
    status = BCryptDecrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, *plaintext, *plaintextSize, &resultLength, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptDecrypt failed");

    // Clean up
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (keyObject) free(keyObject);
}

void win_decrypt_file_aes(char *key_path, char *file_path, 
    char *chaining, char *iv_path, char *output_path) 
{
    FILE *keyFile = fopen(key_path, "rb");
    FILE *ivFile = fopen(iv_path, "rb");
    FILE *inputFile = fopen(file_path, "rb");
    FILE *outputFile = fopen(output_path, "wb");
    MASSERT(keyFile != NULL, "Failed to open key file");
    MASSERT(ivFile != NULL, "Failed to open IV file");
    MASSERT(inputFile != NULL, "Failed to open input file");
    MASSERT(outputFile != NULL, "Failed to open output file");

    fseek(keyFile, 0, SEEK_END);
    DWORD keySize = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);
    BYTE *keyBlob = ALLOC(BYTE, keySize);
    fread(keyBlob, 1, keySize, keyFile);
    fclose(keyFile);

    fseek(ivFile, 0, SEEK_END);
    DWORD ivSize = ftell(ivFile);
    fseek(ivFile, 0, SEEK_SET);
    BYTE *iv = ALLOC(BYTE, ivSize);
    fread(iv, 1, ivSize, ivFile);
    fclose(ivFile);

    BYTE chunk[CHUNK_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(chunk, 1, CHUNK_SIZE, inputFile)) > 0) {
        BYTE *plaintext = NULL;
        DWORD plaintextSize = 0;
        win_decrypt_chunk_aes(chunk, bytesRead, keyBlob, keySize, iv, ivSize, &plaintext, &plaintextSize);
        fwrite(plaintext, 1, plaintextSize, outputFile);
        free(plaintext);
    }

    fclose(inputFile);
    fclose(outputFile);
    free(keyBlob);
    free(iv);
}

#endif // _WIN32

int main(int argc, const char *argv[]) {
    char *key_path = NULL;
    char *file_path = NULL;
    char *chaining = NULL;
    char *iv_path = NULL;
    char *output_path = NULL;
    char *mode = NULL;

    static const char *const usages[] = {
        "cifs [options] [[--] args]",
        "cifs [options]",
        "cifs",
        NULL,
    };

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_STRING('m', "mode", &mode,
            "mode of operation, can be 'keygen', 'ivgen', 'enc' or 'dec'", NULL, 0, 0),

        // для генерации ключа:
        // [out] путь к файлу ключа
        OPT_GROUP(C_HEADER "Key generation" C_RESET " "),
        OPT_STRING('g', "gen-key", &key_path,
            "path to key file", NULL, 0, 0),

        // для генерации инициализирующего вектора:
        // [out] путь к файлу инициализирующего вектора
        OPT_GROUP(C_HEADER "IV generation" C_RESET " "),
        OPT_STRING('g', "gen-key", NULL,
            "path to initialization vector", NULL, 0, 0),

        // для шифрования:
        // [in] путь к файлу ключа
        // [in] путь к файлу для шифрования
        // [in] режим сцепления блоков
        // [out] путь к инициализирующему вектору
        // [out] путь к зашифрованному файлу
        OPT_GROUP(C_HEADER "Encryption" C_RESET " "),
        OPT_STRING('k', "key", &key_path, 
            "path to key file", NULL, 0, 0),
        OPT_STRING('i', "iv", &iv_path,
            "path to initialization vector", NULL, 0, 0),
        OPT_STRING('f', "file", &file_path,
            "path to file for encryption", NULL, 0, 0),
        OPT_STRING('c', "chaining", &chaining,
            "block chaining mode", NULL, 0, 0),
        OPT_STRING('o', "output", &output_path,
            "path to output file", NULL, 0, 0),

        // для дешифрования:
        // [in] путь к файлу ключа
        // [in] путь к инициализирующему вектору
        // [in] путь к зашифрованному файлу
        // [in] режим сцепления блоков
        // [out] путь к расшифрованному файлу
        OPT_GROUP(C_HEADER "Decryption" C_RESET " "),
        OPT_STRING('k', "key", NULL,
            "path to key file", NULL, 0, 0),
        OPT_STRING('i', "iv", NULL,
            "path to initialization vector", NULL, 0, 0),
        OPT_STRING('f', "file", NULL,
            "path to encrypted file", NULL, 0, 0),
        OPT_STRING('c', "chaining", NULL,
            "block chaining mode", NULL, 0, 0),
        OPT_STRING('o', "output", NULL,
            "path to output file", NULL, 0, 0),

        OPT_END(),
    };
    
    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);

    const char *argparse_top_msg = "\n" C_HEADER "TMP opening msg" C_RESET " ";
    const char *argparse_bottom_msg = "\n" IME_ESC IME_BRIGHT_BLACK IME_ESC_END\
        "For more info go to Git repo: "                                       \
        "https://github.com/Kseen715/xxx" C_RESET " ";
    argparse_describe(&argparse, argparse_top_msg, argparse_bottom_msg);
    argc = argparse_parse(&argparse, argc, argv);

    iv_path = key_path;

    switch (mode[0])
    {
    case 'k':
        printf("%s", C_CYAN "Key generation" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: Key path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
        printf("%d\n", kpp_keygen("ecb(aes)"));
#endif // _LINUX
#ifdef _WIN32
        win_generate_aes_key(key_path);

        BYTE *keyBlob = NULL;
        DWORD keySize = 0;
        win_read_aes_key(key_path, &keyBlob, &keySize);
        printf("Key: ");
        print_byte_array_hex(keyBlob, keySize);

        if (keyBlob) HeapFree(GetProcessHeap(), 0, keyBlob);
#endif // _WIN32
        break;
    case 'i':
        printf("%s", C_CYAN "IV generation" C_RESET "\n");
        if (iv_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: IV path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
        win_generate_aes_iv(iv_path);

        BYTE *ivBlob = NULL;
        DWORD ivSize = 0;
        win_read_aes_iv(iv_path, &ivBlob, &ivSize);
        printf("IV: ");
        print_byte_array_hex(ivBlob, ivSize);

        if (ivBlob) HeapFree(GetProcessHeap(), 0, ivBlob);
#endif // _WIN32
        break;
    case 'e':
        printf("%s", C_CYAN "Encryption" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: Key path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (file_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: File path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (chaining == NULL)
        {
            printf("%s", C_ERROR "ERROR: Chaining mode is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (iv_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: IV path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (output_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: Output path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
        win_encrypt_file_aes(key_path, file_path, chaining, iv_path, output_path);
#endif // _WIN32
        break;
    case 'd':
        printf("%s", C_CYAN "Decryption" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: Key path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (iv_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: IV path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (file_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: File path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (chaining == NULL)
        {
            printf("%s", C_ERROR "ERROR: Chaining mode is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (output_path == NULL)
        {
            printf("%s", C_ERROR "ERROR: Output path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
#endif // _WIN32
        break;
    default:
        printf("%s", C_ERROR "ERROR: Unknown mode" C_RESET "\n");
        argparse_usage(&argparse);
        break;
    }

    return 0;
}
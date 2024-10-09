#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

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

/// @brief Assert a condition
/// @param cond [in] condition to assert
/// @param msg [in] message to print if the condition is false
#define MASSERT(cond, msg)                                              \
    if (!(cond))                                                        \
    {                                                                   \
        printf(C_ERROR);                                                \
        printf("[ASSERTION FAILED] (%lld) <%s:%d:%s> %s",               \
               (long long)(cond), __FILE__, __LINE__, __func__, msg);   \
        printf(C_RESET "\n");                                           \
        exit(-1);                                                       \
    }

// Preferrable allocators

/// @brief Allocate memory for an array of type T
/// @param T [in] type of the array
/// @param size [in] size of the array
/// @return pointer to the allocated memory
#define ALLOC(T, size) ((T *)malloc((size) * sizeof(T)))

/// @brief Allocate memory for an array of type T and set it to zero
/// @param T [in] type of the array
/// @param size [in] size of the array
/// @return pointer to the allocated memory
#define CALLOC(T, size) ((T *)calloc((size), sizeof(T)))

/// @brief Reallocate memory for an array of type T
/// @param T [in] type of the array
/// @param ptr [in] pointer to the array
/// @param size [in] size of the array
#define REALLOC(T, ptr, size) ((T *)realloc(ptr, (size) * sizeof(T)))

/// @brief Free memory
/// @param ptr [in] pointer to the memory
#define FREE(ptr)    \
    if (ptr != NULL) \
    {                \
        free(ptr);   \
        ptr = NULL;  \
    }

/// @brief Start progress bar
/// @param pbar [in] name of the progress bar
/// @param len [in] length of the progress bar
#define START_PROGRESS_BAR(pbar, len) \
    char __##pbar[len] = {0};         \
    memset(__##pbar, '#', sizeof(__##pbar) - 1)

/// @brief Print progress bar
/// @param pbar [in] name of the progress bar
/// @param per [in] percentage of the progress
/// @param fmt [in] format string additional information
/// @param ... [in] additional information for the format string
#define PROGRESS_BAR_RUNING(pbar, per, fmt, ...) ({                 \
    float p = per >= 100.0 ? 100.0 : per;                           \
    int left = (p / 100.0) * (sizeof(__##pbar) - 1);                \
    int right = (sizeof(__##pbar) - 1) - left;                      \
    printf("\r[%.*s%*s] %.0f%%" fmt, left, __##pbar, right, "",     \
        (float)per, __VA_ARGS__);                                   \
})

/// @brief Update progress bar
/// @param pbar [in] name of the progress bar
/// @param i [in] current iteration
/// @param numIterations [in] total number of iterations
#define UPDATE_PROGRESS_BAR(pbar, i, numIterations)                     \
    PROGRESS_BAR_RUNING(pbar, (float)(i + 1) / numIterations * 100,     \
        " (%lld/%lld)", (long long)(i + 1), (long long)numIterations);  \
    if (numIterations == i + 1) {                                       \
        printf("\n");                                                   \
    }                                                                   \

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
/// @param byte [in] byte to print
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
/// @param data [in] array of integers
/// @param data_size [in] array size
/// @param str [in] pointer to the result
/// @warning The result must be freed after usage
void convert_array_to_str(unsigned long long int *data, size_t data_size, 
                          char **str)
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
        printf("%02X", (uint8_t)array[i]);
    }
    printf("\n");
}

/// @brief Lowercase string
/// @param str [in/out] string to convert
void str_lower(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

/// @brief Lowercase wide string
/// @param str [in/out] string to convert
void wstr_lower(wchar_t *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = towlower(str[i]);
    }
}

/// @brief Check if substring is in the string
/// @param str [in] string
/// @param substr [in] substring
/// @return true if substring is in the string
bool is_in_str(const char *str, const char *substr) {
    return strstr(str, substr) != NULL;
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
#define AES_KEY_BYTE_SIZE 16 // 128 bits
#define AES_KEY_BIT_SIZE AES_KEY_BYTE_SIZE * 8
// #define CHUNK_SIZE 1024 * 1024 * 1024 // 1024 MB
#define CHUNK_SIZE 1024 * 1024 // 1 MB

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
    keyMaterial = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_KEY_BYTE_SIZE);
    MASSERT(keyMaterial != NULL, "HeapAlloc failed");

    // Generate random key material
    status = BCryptGenRandom(NULL, keyMaterial, AES_KEY_BYTE_SIZE, 
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    MASSERT(NT_SUCCESS(status), "BCryptGenRandom failed");

    // Generate the key
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, keyObject, 
        keyObjectLength, keyMaterial, AES_KEY_BYTE_SIZE, 0);
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
        printf("AES%d key generated and saved to \"%s\"\n", 
            AES_KEY_BIT_SIZE, key_path);
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
        if (*keyBlob) {
            fread(*keyBlob, 1, (size_t)*keySize, keyFile);
            fclose(keyFile);
            printf("Key read from file \"%s\"\n", key_path);
        } else {
            printf("Failed to allocate memory for key\n");
        }
    } else {
        printf("Failed to open file for reading\n");
    }
}

/// @brief Generate AES initialization vector and save it to a file
/// @param iv_path [in] path to the IV file
void win_generate_aes_iv(char *iv_path) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;
    DWORD ivSize = AES_KEY_BYTE_SIZE; // AES block size is 16 bytes
    BYTE iv[AES_KEY_BYTE_SIZE];
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

    printf("IV(%d) generated and saved to \"%s\"\n", AES_KEY_BIT_SIZE, iv_path);

    // Clean up
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}

/// @brief Read AES initialization vector from file
/// @param iv_path [in] path to the IV file
/// @param ivBlob [out] pointer to the IV
/// @param ivSize [out] pointer to the IV size
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

    printf("IV read from file \"%s\"\n", iv_path);
}

/// @brief Encrypt chunk using AES
/// @param chunk [in]
/// @param chunk_size [in] size of the chunk
/// @param hAlgorithm [in] algorithm handle
/// @param hKey [in] key handle
/// @param iv [in] initialization vector
/// @param ivSize [in] size of the initialization vector
/// @param ciphertext [out] pointer to the ciphertext
/// @param ciphertextSize [out] pointer to the ciphertext size
void win_enc_chunk_aes(BYTE *chunk, DWORD chunk_size, 
                       BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hKey, 
                       BYTE *iv, DWORD ivSize, 
                       BYTE **ciphertext, DWORD *ciphertextSize) 
{
    NTSTATUS status;
    DWORD resultLength = 0;

    // Calculate the buffer size for the ciphertext
    status = BCryptEncrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, NULL, 0, 
                           ciphertextSize, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptEncrypt failed");

#ifdef _DEBUG
    printf("chunk_size: %lu\n", chunk_size);
#endif // _DEBUG

    // Allocate the ciphertext buffer
    *ciphertext = ALLOC(BYTE, *ciphertextSize);
    MASSERT(*ciphertext != NULL, "HeapAlloc failed");

    // Perform the encryption
    status = BCryptEncrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, 
                           *ciphertext, *ciphertextSize, &resultLength, 
                           BCRYPT_BLOCK_PADDING);    

    // get chaining mode
    wchar_t chainingMode[64]; // Buffer to hold the chaining mode
    DWORD chainingModeSize = sizeof(chainingMode);
    ULONG result = 0;
    status = BCryptGetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, 
                               (PBYTE)chainingMode, chainingModeSize, 
                               &result, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // if (wcscmp(chainingMode, (wchar_t *)BCRYPT_CHAIN_MODE_ECB) == 0) {
    //     *ciphertextSize = chunk_size;
    // } else {
    //     *ciphertextSize = resultLength;
    // }
#ifdef _DEBUG
    printf("status: %ld\n", status);
    printf("cipherTextSize: %lu\n", *ciphertextSize);
    printf("resultLength: %lu\n", resultLength);
#endif // _DEBUG
    MASSERT(NT_SUCCESS(status), "BCryptEncrypt failed");
}

/// @brief Decrypt chunk using AES
/// @param chunk [in]
/// @param chunk_size [in] size of the chunk 
/// @param hAlgorithm [in] algorithm handle
/// @param hKey [in] key handle
/// @param iv [in] initialization vector
/// @param ivSize [in] size of the initialization vector
/// @param plaintext [out] pointer to the plaintext
/// @param plaintextSize [out] pointer to the plaintext size
void win_dec_chunk_aes(BYTE *chunk, DWORD chunk_size, 
                       BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hKey, 
                       BYTE *iv, DWORD ivSize, 
                       BYTE **plaintext, DWORD *plaintextSize, bool isLastChunk) 
{
    NTSTATUS status;
    DWORD resultLength = 0;

    // Calculate the buffer size for the plaintext
    status = BCryptDecrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, NULL, 0, 
                           plaintextSize, BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptDecrypt failed");


    // Allocate the plaintext buffer
    *plaintext = ALLOC(BYTE, *plaintextSize);
    MASSERT(*plaintext != NULL, "HeapAlloc failed");

    // Perform the decryption
#ifdef _DEBUG
    printf("chunk_size: %lu\n", chunk_size);
    printf("ivSize: %lu\n", ivSize);
    printf("plaintextSize: %lu\n", *plaintextSize);
#endif // _DEBUG
    status = BCryptDecrypt(hKey, chunk, chunk_size, NULL, iv, ivSize, 
                           *plaintext, *plaintextSize, &resultLength, 
                           BCRYPT_BLOCK_PADDING);
    MASSERT(NT_SUCCESS(status), "BCryptDecrypt failed");
                        
    // get chaining mode
    wchar_t chainingMode[64]; // Buffer to hold the chaining mode
    DWORD chainingModeSize = sizeof(chainingMode);
    ULONG result = 0;
    status = BCryptGetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, 
                               (PBYTE)chainingMode, chainingModeSize, 
                               &result, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

        *plaintextSize = resultLength;
    if (wcscmp(chainingMode, (wchar_t *)BCRYPT_CHAIN_MODE_ECB) != 0) {
    }
    // *plaintextSize = resultLength;
    if (isLastChunk) {
        *plaintextSize = resultLength;
    }
#ifdef _DEBUG
    if (isLastChunk) printf("isLastChunk: %d\n", isLastChunk);
    printf("status: %ld\n", status);
    printf("resultLength: %lu\n", resultLength);
    printf("plaintextSize: %lu\n", *plaintextSize);
    printf("hKey: %p\n", hKey);
    printf("iv: ");
    for (DWORD i = 0; i < ivSize; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
#endif // _DEBUG
    // MASSERT(false, "");
}

/// @brief Encrypt file using AES
/// @param key_path [in] path to the key file
/// @param file_path [in] path to the file for encryption
/// @param chaining [in] chaining mode
/// @param iv_path [in] path to the initialization vector
/// @param output_path [in] path to the encrypted file
/// @param chainingMode [in] chaining mode
void win_enc_file_aes(char *key_path, char *file_path, 
                      char *chaining, char *iv_path, char *output_path, 
                      wchar_t* chainingMode) 
{
    FILE *keyFile = fopen(key_path, "rb");
    FILE *inputFile = fopen(file_path, "rb");
    FILE *outputFile = fopen(output_path, "wb");
    MASSERT(keyFile != NULL, "Failed to open key file");
    MASSERT(inputFile != NULL, "Failed to open input file");
    MASSERT(outputFile != NULL, "Failed to open output file");

    DWORD ivSize = 0;
    BYTE *iv = NULL;
    if (wcscmp(chainingMode, (wchar_t *)BCRYPT_CHAIN_MODE_ECB) != 0) {
        FILE *ivFile = fopen(iv_path, "rb");
        MASSERT(ivFile != NULL, "Failed to open IV file");
        fseek(ivFile, 0, SEEK_END);
        ivSize = ftell(ivFile);
        fseek(ivFile, 0, SEEK_SET);
        iv = ALLOC(BYTE, ivSize);
        fread(iv, 1, ivSize, ivFile);
        fclose(ivFile);
    }

    fseek(keyFile, 0, SEEK_END);
    DWORD keySize = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);
    BYTE *keyBlob = ALLOC(BYTE, keySize);
    fread(keyBlob, 1, keySize, keyFile);
    fclose(keyFile);

    fseek(inputFile, 0, SEEK_END);
    DWORD inputSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    DWORD chunk_size = CHUNK_SIZE;
    if (inputSize < chunk_size) {
        chunk_size = inputSize;
    }

    BYTE *chunk = ALLOC(BYTE, chunk_size);

    fseek(inputFile, 0, SEEK_END);
    size_t fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD resultLength = 0;
    BYTE *keyObject = NULL;
    DWORD keyObjectSize = 0;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Set the chaining mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)chainingMode, wcslen(chainingMode) + 1, 0);
    MASSERT(NT_SUCCESS(status), "BCryptSetProperty failed");

#ifdef _DEBUG
    // Get current chaining mode
    wchar_t currentChainingMode[64]; // Buffer to hold the chaining mode
    DWORD chainingModeSize = sizeof(currentChainingMode);
    status = BCryptGetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)currentChainingMode, chainingModeSize, &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");
    wprintf(L"Current chaining mode: %ls\n", currentChainingMode);
#endif // _DEBUG

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjectSize, sizeof(DWORD), &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // Allocate the key object
    keyObject = ALLOC(BYTE, keyObjectSize);
    MASSERT(keyObject != NULL, "HeapAlloc failed");

    // Generate the key from the keyBlob
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, keyBlob, keySize, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGenerateSymmetricKey failed");

    size_t numIterations = (fileSize + chunk_size - 1) / chunk_size; // Calculate the number of chunks
    START_PROGRESS_BAR(pbar, 32);
    for (size_t i = 0; i < numIterations; i++) {
        size_t bytesRead = fread(chunk, 1, chunk_size, inputFile);
        BYTE *ciphertext = NULL;
        DWORD ciphertextSize = 0;
        win_enc_chunk_aes(chunk, bytesRead, hAlgorithm, hKey, iv, ivSize, &ciphertext, &ciphertextSize);
        fwrite(ciphertext, 1, ciphertextSize, outputFile);
#ifdef _DEBUG
        printf("written: %lu  bytes\n", ciphertextSize);
#endif // _DEBUG
        UPDATE_PROGRESS_BAR(pbar, i, numIterations);
        FREE(ciphertext);
    }

    printf("File %s encrypted and saved to %s\n", file_path, output_path);
    // Clean up
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    fclose(inputFile);
    fclose(outputFile);
    FREE(keyObject);
    FREE(keyBlob);
    FREE(iv);
    FREE(chunk);
}

/// @brief Decrypt file using AES
/// @param key_path [in] path to the key file
/// @param file_path [in] path to the file for decryption
/// @param chaining [in] chaining mode
/// @param iv_path [in] path to the initialization vector
/// @param output_path [in] path to the decrypted file
/// @param chainingMode [in] chaining mode
void win_dec_file_aes(char *key_path, char *file_path, 
                      char *chaining, char *iv_path, char *output_path, 
                      wchar_t* chainingMode) 
{
    FILE *keyFile = fopen(key_path, "rb");
    FILE *inputFile = fopen(file_path, "rb");
    FILE *outputFile = fopen(output_path, "wb");
    MASSERT(keyFile != NULL, "Failed to open key file");
    MASSERT(inputFile != NULL, "Failed to open input file");
    MASSERT(outputFile != NULL, "Failed to open output file");

    DWORD ivSize = 0;
    BYTE *iv = NULL;
    if (wcscmp(chainingMode, (wchar_t *)BCRYPT_CHAIN_MODE_ECB) != 0) {
        FILE *ivFile = fopen(iv_path, "rb");
        MASSERT(ivFile != NULL, "Failed to open IV file");
        fseek(ivFile, 0, SEEK_END);
        ivSize = ftell(ivFile);
        fseek(ivFile, 0, SEEK_SET);
        iv = ALLOC(BYTE, ivSize);
        fread(iv, 1, ivSize, ivFile);
        fclose(ivFile);
    }

    fseek(keyFile, 0, SEEK_END);
    DWORD keySize = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);
    BYTE *keyBlob = ALLOC(BYTE, keySize);
    fread(keyBlob, 1, keySize, keyFile);
    fclose(keyFile);

    fseek(inputFile, 0, SEEK_END);
    DWORD inputSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    DWORD chunk_size = CHUNK_SIZE;
    if (inputSize < chunk_size) {
        chunk_size = inputSize;
    }
    // chunk_size must be multiple of AES block size plus 
    // additional bytes (d + 16) & ~15
    // if (wcscmp(chainingMode, BCRYPT_CHAIN_MODE_CBC) == 0 ||
        // wcscmp(chainingMode, BCRYPT_CHAIN_MODE_ECB) == 0) {
    // }
    chunk_size = (chunk_size + AES_KEY_BYTE_SIZE) & ~15;

    BYTE *chunk = ALLOC(BYTE, chunk_size);

    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD resultLength = 0;
    BYTE *keyObject = NULL;
    DWORD keyObjectSize = 0;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 
                                         NULL, 0);
    MASSERT(NT_SUCCESS(status), "BCryptOpenAlgorithmProvider failed");

    // Set the chaining mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, 
                               (PBYTE)chainingMode, wcslen(chainingMode), 0);
    MASSERT(NT_SUCCESS(status), "BCryptSetProperty failed");

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, 
                               (PBYTE)&keyObjectSize, sizeof(DWORD), 
                               &resultLength, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGetProperty failed");

    // Allocate the key object
    keyObject = ALLOC(BYTE, keyObjectSize);
    MASSERT(keyObject != NULL, "HeapAlloc failed");

    // Generate the key from the keyBlob
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, keyObject, 
                                        keyObjectSize, keyBlob, keySize, 0);
    MASSERT(NT_SUCCESS(status), "BCryptGenerateSymmetricKey failed");

    fseek(inputFile, 0, SEEK_END);
    size_t fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // Calculate the number of chunks
    size_t numIterations = (fileSize + chunk_size - 1) / chunk_size; 
    START_PROGRESS_BAR(pbar, 32);
    for (size_t i = 0; i < numIterations; i++) {
        size_t bytesRead = fread(chunk, 1, chunk_size, inputFile);
        BYTE *plaintext = NULL;
        DWORD plaintextSize = 0;
        win_dec_chunk_aes(chunk, bytesRead, hAlgorithm, hKey, iv, ivSize, 
                          &plaintext, &plaintextSize, i == numIterations - 1);
#ifdef _DEBUG
        printf("written: %lu  bytes\n", plaintextSize);
#endif // _DEBUG
        fwrite(plaintext, 1, plaintextSize, outputFile);
        UPDATE_PROGRESS_BAR(pbar, i, numIterations);
        FREE(plaintext);
    }

    printf("File %s decrypted and saved to %s\n", file_path, output_path); 
    // Clean up
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    fclose(inputFile);
    fclose(outputFile);
    FREE(keyObject);
    FREE(keyBlob);
    FREE(iv);
    FREE(chunk);
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
        OPT_STRING('m', "mode", &mode,                          \
                   "mode of operation, "                        \
                   "can be 'keygen', 'ivgen', 'enc' or 'dec'",  \
                   NULL, 0, 0),                                 \

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
                   "block chaining mode, can be CBC, CFB, ECB", NULL, 0, 0),
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
                   "block chaining mode, can be CBC, CFB, ECB", NULL, 0, 0),
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
    if (argc == 0)
    {
        argparse_usage(&argparse);
        exit(0);
    }
    argc = argparse_parse(&argparse, argc, argv);


    wchar_t *chainingMode = NULL;

    if (mode[0] == 'i'){
        iv_path = key_path;
    }

    switch (mode[0])
    {
    case 'k':
        printf("%s", C_CYAN "Key generation" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: Key path is not specified" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
        printf("%d\n", kpp_keygen("ecb(aes)"));
#endif // _LINUX
#ifdef _WIN32
        printf(C_HEADER "Using:" C_RESET "\n");
        printf("  \\- Key path:\t\t\"%s\"\n", key_path);
        printf("\n");
        win_generate_aes_key(key_path);
#ifdef _DEBUG
        BYTE *keyBlob = NULL;
        DWORD keySize = 0;
        win_read_aes_key(key_path, &keyBlob, &keySize);
        printf("keyBlob: %p\n", keyBlob);
        printf("keySize: %ld\n", keySize);
        printf("Key: ");
        print_byte_array_hex(keyBlob, keySize);
        FREE(keyBlob);
        if (keyBlob) HeapFree(GetProcessHeap(), 0, keyBlob);
#endif // _DEBUG
#endif // _WIN32
        break;
    case 'i':
        printf("%s", C_CYAN "IV generation" C_RESET "\n");
        if (iv_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: IV path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
        printf(C_HEADER "Using:" C_RESET "\n");
        printf("  \\- IV path:\t\t\"%s\"\n", iv_path);
        printf("\n");

        win_generate_aes_iv(iv_path);
#ifdef _DEBUG
        BYTE *ivBlob = NULL;
        DWORD ivSize = 0;
        win_read_aes_iv(iv_path, &ivBlob, &ivSize);
        printf("IV: ");
        print_byte_array_hex(ivBlob, ivSize);
        FREE(ivBlob);
        if (ivBlob) HeapFree(GetProcessHeap(), 0, ivBlob);
#endif // _DEBUG
#endif // _WIN32
        break;
    case 'e':
        printf("%s", C_CYAN "Encryption" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s",
                   C_ERROR "ERROR: Key path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (file_path == NULL)
        {
            printf("%s",
                   C_ERROR "ERROR: File path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (chaining == NULL)
        {
            printf("%s",
                   C_ERROR "ERROR: Chaining mode is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (iv_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: IV path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (output_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: Output path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
        str_lower(chaining);

        if (is_in_str(chaining, "cbc"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_CBC;
        }
        else if (is_in_str(chaining, "cfb"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_CFB;
        }
        else if (is_in_str(chaining, "ecb"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_ECB;
        }
        else
        {
            printf("%s", C_ERROR "ERROR: Unknown chaining mode" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }

        printf(C_HEADER "Using:" C_RESET "\n");
        printf("  |- Key path:\t\t\"%s\"\n", key_path);
        printf("  |- IV path:\t\t\"%s\"\n", iv_path);
        printf("  |- Chaining mode:\t%ls\n", chainingMode);
        printf("  |- Input file:\t\"%s\"\n", file_path);
        printf("  \\- Output file:\t\"%s\"\n", output_path);
        printf("\n");

        win_enc_file_aes(key_path, file_path, chaining, iv_path, 
            output_path, chainingMode);
#endif // _WIN32
        break;
    case 'd':
        printf("%s", C_CYAN "Decryption" C_RESET "\n");
        if (key_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: Key path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (iv_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: IV path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (file_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: File path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (chaining == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: Chaining mode is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
        if (output_path == NULL)
        {
            printf("%s", 
                   C_ERROR "ERROR: Output path is not specified" \
                   C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }
#ifdef _LINUX
#endif // _LINUX
#ifdef _WIN32
        str_lower(chaining);

        if (is_in_str(chaining, "cbc"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_CBC;
        }
        else if (is_in_str(chaining, "cfb"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_CFB;
        }
        else if (is_in_str(chaining, "ecb"))
        {
            chainingMode = BCRYPT_CHAIN_MODE_ECB;
        }
        else
        {
            printf("%s", C_ERROR "ERROR: Unknown chaining mode" C_RESET "\n");
            argparse_usage(&argparse);
            exit(1);
        }

        printf(C_HEADER "Using:" C_RESET "\n");
        printf("  |- Key path:\t\t\"%s\"\n", key_path);
        printf("  |- IV path:\t\t\"%s\"\n", iv_path);
        printf("  |- Chaining mode:\t%ls\n", chainingMode);
        printf("  |- Input file:\t\"%s\"\n", file_path);
        printf("  \\- Output file:\t\"%s\"\n", output_path);
        printf("\n");

        win_dec_file_aes(key_path, file_path, chaining, iv_path, 
            output_path, chainingMode);
#endif // _WIN32
        break;
    default:
        printf("%s", C_ERROR "ERROR: Unknown mode" C_RESET "\n");
        argparse_usage(&argparse);
        break;
    }

    return 0;
}
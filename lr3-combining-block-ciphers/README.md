# Combinig block ciphers

There are many ways to combine block algorithms to get new algorithms. The impetus behind these schemes is to try to increase security without going through the trouble of designing a new algorithm. DES is a secure algorithm; it has been cryptanalyzed for a good 20 years and the most practical way to break it is still brute force. However, the key is too short. Wouldn't it be nice to use DES as a building block for another algorithm with a longer key?

Multiple encryption is one combination technique: using an algorithm to encrypt the same plaintext block multiple times with multiple keys. Cascading is like multiple encryption, but uses different algorithms. There are other techniques.

Encrypting a plaintext block twice with the same key, whether with the same algorithm or a different one, is not smart. For the same algorithm, it does not affect the complexity of a brute-force search. (Remember, you assume a cryptanalyst knows the algorithm including the number of encryptions used.) For different algorithms, it may or may not. If you are going to use any of the techniques in this chapter, make sure the multiple keys are different and independent.

## Used techniques

- 3DES ECB
- 3DES Inner CBC
- 3DES Outer CBC
- 3DES with pad

### 3DES ECB

### 3DES Inner CBC

### 3DES Outer CBC

### 3DES with pad

## Result of benchmakrs
![plot](https://github.com/user-attachments/assets/311a8778-fe19-4b0f-99da-e8e93da5a32f)

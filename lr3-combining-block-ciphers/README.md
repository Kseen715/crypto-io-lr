# Combinig block ciphers

A multitude of techniques exist for the combination of block algorithms, resulting in the generation of novel algorithms. The rationale behind these approaches is to enhance security without the necessity of developing an entirely novel algorithm. DES is a secure algorithm; it has been subjected to cryptanalysis for approximately 20 years, and the most practical method for breaking it remains brute force. Nevertheless, the key is insufficiently lengthy. It would be advantageous to utilise DES as a foundation for an alternative algorithm with a longer key.

A further technique for combining algorithms is to use one algorithm to encrypt the same plaintext block on multiple occasions, with multiple keys. Cascading is a technique that employs a series of encryption algorithms, each applied to the same plaintext block. There are other techniques that may be employed.

The encryption of a plaintext block on two occasions with the same key, whether with the same or a different algorithm, is an unwise approach. The complexity of a brute-force search is not affected by the use of the same algorithm. It should be noted that the assumption is made that the cryptanalyst is aware of the algorithm, including the number of encryptions that have been employed. In the case of different algorithms, this is not necessarily the case. In the event that any of the techniques outlined in this chapter are to be employed, it is imperative that the multiple keys in question are distinct and independent.

## Used techniques

- 3DES ECB
- native 3DES
- 3DES Inner CBC
- 3DES Outer CBC
- 3DES with pad


### 3DES ECB

Common implementations of 3DES. 

### native 3DES

Pycryptodome library implementation of 3DES. 

### 3DES Inner CBC

In an internal CBC, block cohesion occurs at each of the three stages of encryption.

### 3DES Outer CBC

In an external CBC, the coupling functions as if the three encryption steps were a single, unified process.

### 3DES with pad

In the 3DES with pad mode, a string of random bits half a block long is appended to the text between the first and second encryptions and between the second and third encryptions. This ensures that the encryption blocks overlap.

## Result of benchmakrs
![plot](https://github.com/user-attachments/assets/311a8778-fe19-4b0f-99da-e8e93da5a32f)

 ## IMPLEMENTATION OF RSA
 # AIM :
 To write a C program to implement the RSA encryption algorithm.

## ALGORITHM:
STEP-1: Select two co-prime numbers as p and q.

STEP-2: Compute n as the product of p and q.

STEP-3: Compute (p-1)*(q-1) and store it in z.## EXERCISE 02 : CRYPTOGRAPHY - ADVANCED TECHNIQUES
___________________________________
## REGISTER NUMBER: 212221040057
___________________________________
 
 ## IMPLEMENTATION OF RSA
 # AIM :
 To write a C program to implement the RSA encryption algorithm.

## ALGORITHM:
STEP-1: Select two co-prime numbers as p and q.

STEP-2: Compute n as the product of p and q.

STEP-3: Compute (p-1)*(q-1) and store it in z.

STEP-4: Select a random prime number e that is less than that of z.

STEP-5: Compute the private key, d as e *
mod-1
(z).

STEP-6: The cipher text is computed as messagee *

STEP-7: Decryption is done as cipherdmod n.

## PROGRAM:
```
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

void generateRSAKeys(int *n, int *e, int *d) {
    int p, q;
    printf("Enter two prime numbers: ");
    scanf("%d %d", &p, &q);

    *n = p * q;

    int phi = (p - 1) * (q - 1);

    
    *e = 5;

    *d = 0;
    while ((*d * *e) % phi != 1) {
        (*d)++;
    }
}

int modExp(int base, int exponent, int modulus) {
    int result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

int encrypt(int message, int publicKey, int modulus) {
    return modExp(message, publicKey, modulus);
}

int decrypt(int ciphertext, int privateKey, int modulus) {
    return modExp(ciphertext, privateKey, modulus);
}

int main() {
    int n, e, d;
    int plaintext;
    
    printf("Enter plaintext: ");
    scanf("%d", &plaintext);
    
    generateRSAKeys(&n, &e, &d);
    
    printf("Original message: %d\n", plaintext);
    
    int ciphertext = encrypt(plaintext, e, n);
    printf("Encrypted message: %d\n", ciphertext);
    
    int decryptedMessage = decrypt(ciphertext, d, n);
    printf("Decrypted message: %d\n", decryptedMessage);
    
    return 0;
}
```
## OUTPUT:
![WhatsApp Image 2024-03-15 at 21 53 18](https://github.com/IsaacAIML2023/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/103128410/91c3fe38-c47b-4b09-bfbc-24c4db07db29)

## RESULT :

Thus the C program to implement RSA encryption technique had been implemented successfully.



________________________________________________________________________

## IMPLEMENTATION OF DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

## AIM:

To implement the Diffie-Hellman Key Exchange algorithm using C language.


## ALGORITHM:

STEP-1: Both Alice and Bob shares the same public keys g and p.

STEP-2: Alice selects a random public key a.

STEP-3: Alice computes his secret key A as g
a mod p.

STEP-4: Then Alice sends A to Bob.


STEP-5: Similarly Bob also selects a public key b and computes his secret
key as B and sends the same back to Alice.


STEP-6: Now both of them compute their common secret key as the other
one’s secret key power of a mod p.

## PROGRAM: 

```
#include <stdio.h>
#include <math.h>

int power(int a, int b, int mod) {
    int result = 1;
    a = a % mod;
    while (b > 0) {
        if (b & 1)
            result = (result * a) % mod;
        b = b >> 1;
        a = (a * a) % mod;
    }
    return result;
}

void diffieHellman(int prime, int root) {
    int privateKeyA, privateKeyB;
    int publicKeyA, publicKeyB;
    int secretKeyA, secretKeyB;

    printf("Enter private key for user A: ");
    scanf("%d", &privateKeyA);
    printf("Enter private key for user B: ");
    scanf("%d", &privateKeyB);

    
    publicKeyA = power(root, privateKeyA, prime);
    publicKeyB = power(root, privateKeyB, prime);

    secretKeyA = power(publicKeyB, privateKeyA, prime);
    secretKeyB = power(publicKeyA, privateKeyB, prime);

    printf("Shared secret key computed by user A: %d\n", secretKeyA);
    printf("Shared secret key computed by user B: %d\n", secretKeyB);
}

int main() {
    int prime, root;

    printf("Enter prime number: ");
    scanf("%d", &prime);
    printf("Enter primitive root: ");
    scanf("%d", &root);

    diffieHellman(prime, root);

    return 0;
}
```
## OUTPUT:
![WhatsApp Image 2024-03-15 at 21 41 21](https://github.com/IsaacAIML2023/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/103128410/1fd673dd-8ddb-4c9a-84c6-d0f5c439806e)



## RESULT: 

Thus the Diffie-Hellman key exchange algorithm had been successfully implemented using C.


________________________________________________________________


## IMPLEMENTATION OF DES ALGORITHM

## AIM:
To write a program to implement Data Encryption Standard (DES)

## ALGORITHM :

STEP-1: Read the 64-bit plain text.

STEP-2: Split it into two 32-bit blocks and store it in two different arrays.

STEP-3: Perform XOR operation between these two arrays.

STEP-4: The output obtained is stored as the second 32-bit sequence and the
original second 32-bit sequence forms the first part.

STEP-5: Thus the encrypted 64-bit cipher text is obtained in this way. Repeat the
same process for the remaining plain text characters.

### PROGRAM :

```
import javax.swing.*;
import java.security.SecureRandom; import javax.crypto.Cipher;
import javax.crypto.KeyGenerator; import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; import java.util.Random ;
class desi {
    byte[] skey = new byte[1000]; String skeyString;
    static byte[] raw;
    String inputMessage,encryptedData,decryptedMessage; public desi()
    {
        try
        {
            generateSymmetricKey(); inputMessage=JOptionPane.showInputDialog(null,"Enter message to encrypt");
            byte[] ibyte = inputMessage.getBytes(); byte[] ebyte=encrypt(raw, ibyte);
            String encryptedData = new String(ebyte); System.out.println("Encrypted message "+encryptedData); JOptionPane.showMessageDialog(null,"Encrypted Data "+"\n"+encryptedData);
            byte[] dbyte= decrypt(raw,ebyte);
            String decryptedMessage = new String(dbyte); System.out.println("Decrypted message "+decryptedMessage); JOptionPane.showMessageDialog(null,"Decrypted Data "+"\n"+decryptedMessage);
        }
        catch(Exception e)
        {
            System.out.println(e);
        }
    }


    void generateSymmetricKey() { try {
        Random r = new Random(); int num = r.nextInt(10000);
        String knum = String.valueOf(num); byte[] knumb = knum.getBytes(); skey=getRawKey(knumb);
        skeyString = new String(skey);
        System.out.println("DES Symmetric key = "+skeyString);
    }
    catch(Exception e)
    {
        System.out.println(e);
    }
    }
    private static byte[] getRawKey(byte[] seed) throws Exception
    {
        KeyGenerator kgen = KeyGenerator.getInstance("DES"); SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); sr.setSeed(seed);
        kgen.init(56, sr);
        SecretKey skey = kgen.generateKey(); raw = skey.getEncoded();
        return raw;
    }
    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
        Cipher cipher = Cipher.getInstance("DES"); cipher.init(Cipher.ENCRYPT_MODE, skeySpec); byte[] encrypted = cipher.doFinal(clear); return encrypted;
    }
    private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception
    {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
        Cipher cipher = Cipher.getInstance("DES"); cipher.init(Cipher.DECRYPT_MODE, skeySpec); byte[] decrypted = cipher.doFinal(encrypted); return decrypted;
    }
    public static void main(String args[]) { desi des = new desi();
    }
}

```
## OUTPUT:

![Screenshot (523)](https://github.com/IsaacAIML2023/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/103128410/a825b571-db4a-4e80-95f8-dc829793f74e)
![Screenshot (524)](https://github.com/IsaacAIML2023/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/103128410/f716e49d-ddb6-48d5-9136-843001a0276e)
![Screenshot (525)](https://github.com/IsaacAIML2023/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/103128410/21b3897e-fa69-46bf-bc3b-30d2ce85b46d)


## RESULT:

Thus the data encryption standard algorithm had been implemented successfully using java.



STEP-4: Select a random prime number e that is less than that of z.

STEP-5: Compute the private key, d as e *
mod-1
(z).

STEP-6: The cipher text is computed as messagee *

STEP-7: Decryption is done as cipherdmod n.

## PROGRAM:
```
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
// Function to calculate greatest common divisor (GCD)
int gcd(int a, int b) {
if (b == 0)
return a;
return gcd(b, a % b);
}
// Function to generate RSA keys
void generateRSAKeys(int *n, int *e, int *d) {
// Choose two prime numbers (p and q)
int p;
int q;
printf("enter two prime numbers:");
scanf("%d %d",&p,&q);
// Calculate n = p * q
*n = p * q;
// Calculate Euler's totient function (φ(n))
int phi = (p - 1) * (q - 1);
// Choose a public exponent (e) such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
*e = 5; // You can choose a different value for e, typically a prime number
// Calculate the private exponent (d) such that (d * e) % φ(n) = 1
*d = 0;
while ((*d * *e) % phi != 1) {
(*d)++;
}
}
// Function to perform modular exponentiation (base^exponent % modulus)
int modExp(int base, int exponent, int modulus) {
int result = 1;
while (exponent > 0) {
if (exponent % 2 == 1) {
result = (result * base) % modulus;
}
base = (base * base) % modulus;
exponent /= 2;
}
return result;
}
// Function to encrypt a message using the public key
int encrypt(int message, int publicKey, int modulus) {
return modExp(message, publicKey, modulus);
}
// Function to decrypt a message using the private key
int decrypt(int ciphertext, int privateKey, int modulus) {
return modExp(ciphertext, privateKey, modulus);
}
int main() {
int n, e, d;
int plaintext;
printf("enter plaintext:");
scanf("%d",&plaintext);
generateRSAKeys(&n, &e, &d);
printf("Original message: %d\n", plaintext);
int ciphertext = encrypt(plaintext, e, n);
printf("Encrypted message: %d\n", ciphertext);
int decryptedMessage = decrypt(ciphertext, d, n);
printf("Decrypted message: %d\n", decryptedMessage);
return 0;
}
```
## OUTPUT:
![Screenshot 2024-03-05 113517](https://github.com/AlluguriSrikrishnateja/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/118343892/b96f8704-db74-4fb0-835d-078d58644625)


## RESULT :

Thus the C program to implement RSA encryption technique had been
implemented successfully

## IMPLEMENTATION OF AES
## AIM:
To use Advanced Encryption Standard (AES) Algorithm for a practical
application like URL Encryption.
## ALGORITHM:
1. AES is based on a design principle known as a substitution–permutation.
2. AES does not use a Feistel network like DES, it uses variant of Rijndael.
3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
4. AES operates on a 4 × 4 column-major order array of bytes, termed the state
## PROGRAM:
## AES.java
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class AES {
 private static SecretKeySpec secretKey;
 private static byte[] key;
 public static void setKey(String myKey) {
 MessageDigest sha = null;
 try {
 key = myKey.getBytes("UTF-8");
 sha = MessageDigest.getInstance("SHA-1");
 key = sha.digest(key);
 key = Arrays.copyOf(key, 16);
 secretKey = new SecretKeySpec(key, "AES");
 } catch (NoSuchAlgorithmException e) {
 e.printStackTrace();
 } catch (UnsupportedEncodingException e) {
 e.printStackTrace();
 }
 }
 public static String encrypt(String strToEncrypt, String secret) {
 try {
 setKey(secret);
 Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
 cipher.init(Cipher.ENCRYPT_MODE, secretKey);
 return
Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
 } catch (Exception e) {
 System.out.println("Error while encrypting: " + e.toString());
 }
 return null;
 }
 public static String decrypt(String strToDecrypt, String secret) {
 try {
 setKey(secret);
 Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
 cipher.init(Cipher.DECRYPT_MODE, secretKey);
 return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
 } catch (Exception e) {
 System.out.println("Error while decrypting: " + e.toString());
 }
 return null;
 }
 public static void main(String[] args) {
 final String secretKey = "annaUniversity";
 String originalString = "www.annauniv.edu";
 String encryptedString = AES.encrypt(originalString, secretKey);
 String decryptedString = AES.decrypt(encryptedString, secretKey);
 System.out.println("URL Encryption Using AES Algorithm\n------------");
 System.out.println("Original URL : " + originalString);
 System.out.println("Encrypted URL : " + encryptedString);
 System.out.println("Decrypted URL : " + decryptedString);
 }
}
   ## OUTPUT:
URL Encryption Using AES Algorithm
-------------------------------------------------
Original URL : www.annauniv.edu
Encrypted URL : vibpFJW6Cvs5Y+L7t4N6YWWe07+JzS1d3CU2h3mEvEg=
Decrypted URL : www.annauniv.edu

## RESULT:



## IMPLEMENTATION OF DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

## AIM:

To implement the Diffie-Hellman Key Exchange algorithm using C language.


## ALGORITHM:

STEP-1: Both Alice and Bob shares the same public keys g and p.

STEP-2: Alice selects a random public key a.

STEP-3: Alice computes his secret key A as g
a mod p.

STEP-4: Then Alice sends A to Bob.


STEP-5: Similarly Bob also selects a public key b and computes his secret
key as B and sends the same back to Alice.


STEP-6: Now both of them compute their common secret key as the other
one’s secret key power of a mod p.

## PROGRAM: 

```
#include <math.h>
#include <stdio.h>
// Power function to return value of a ^ b mod P
long long int power(long long int a, long long int b,
long long int P)
{
if (b == 1)
return a;
else
return (((long long int)pow(a, b)) % P);
}
int main()
{
long long int P, G, x, a, y, b, ka, kb;
// Both the persons will be agreed upon the
// public keys G and P
printf("Enter the value of P:");
scanf("%lld",&P); // A prime number P is taken
printf("The value of P : %lld\n", P);
printf("Enter the value of G:");
scanf("%lld",&G); // A primitive root for P, G is taken
printf("The value of G : %lld\n\n", G);
// Alice will choose the private key a
a = 4; // a is the chosen private key
printf("The private key a for Alice : %lld\n", a);
x = power(G, a, P); // gets the generated key
// Bob will choose the private key b
b = 3; // b is the chosen private key
printf("The private key b for Bob : %lld\n\n", b);
y = power(G, b, P); // gets the generated key
// Generating the secret key after the exchange
// of keys
ka = power(y, a, P); // Secret key for Alice
kb = power(x, b, P); // Secret key for Bob
printf("Secret key for the Alice is : %lld\n", ka);
printf("Secret Key for the Bob is : %lld\n", kb);
return 0;
}
```
## OUTPUT:

<img width="342" alt="image" src="https://github.com/AlluguriSrikrishnateja/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/118343892/a3f5b0fa-ef81-4215-9521-2a16c87cef68">


## RESULT: 

Thus the Diffie-Hellman key exchange algorithm had been successfully
implemented using C.





## IMPLEMENTATION OF DES ALGORITHM

## AIM:
To write a program to implement Data Encryption Standard (DES)

## ALGORITHM :

STEP-1: Read the 64-bit plain text.

STEP-2: Split it into two 32-bit blocks and store it in two different arrays.

STEP-3: Perform XOR operation between these two arrays.

STEP-4: The output obtained is stored as the second 32-bit sequence and the
original second 32-bit sequence forms the first part.

STEP-5: Thus the encrypted 64-bit cipher text is obtained in this way. Repeat the
same process for the remaining plain text characters.

### PROGRAM :

```
from cryptography.fernet import Fernet
message = input()
key = Fernet.generate_key()
fernet = Fernet(key)
encMessage = fernet.encrypt(message.encode())
print("original string: ", message)
print("encrypted string: ", encMessage)

decMessage = fernet.decrypt(encMessage).decode()
 
print("decrypted string: ", decMessage)
```
## OUTPUT:

![image](https://github.com/Selvajoel/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/122252838/f9db389a-cf50-412f-9c4c-e41e1357c241)


## RESULT:

Thus the data encryption standard algorithm had been implemented
successfully.


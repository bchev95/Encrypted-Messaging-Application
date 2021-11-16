#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "cryptopp/hex.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

int checkParams(int argc, char* argv)
{
    int ptnum = atoi(argv);
    //Below if checks that the user has provided just one command line argument
    if(argc != 2)
    {
        std::cout << "Error, incorrect number of parameters.\nPlease provide an integer port number to connect to.\nExample: ./server 12000" << std::endl;
        return -1;
    }

    //Below while loop checks whether argv[1] is of type int
    while(*argv != 0)
    {
        if(!isdigit(*argv++))
        {
            std::cout << "Please enter an integer port number to connect to. Example: ./server 12000" << std::endl;
            return -1;
        }
    }
    //Check that the port number specified is within the valid range of ports
    if(ptnum < 1 || ptnum > 65535)
    {
        std::cout << "This is not a valid port number, try within the range 1 - 65535" << std::endl;
        return -1;
    }
    return 0;
}
//This function prints out the string sent to it along with the sender and the current time in format: HH/MM/SS
void printMessage(std::string message, std::string sender)
{
    std::size_t index = message.find('\n');
    std::string finalMessage = message.substr(0, index);
    time_t theTime = time(NULL);
    char timeBuf[20];
    strftime(timeBuf, 20, "%T", localtime(&theTime));
    printf("%s", timeBuf);
    std::cout << ": " << sender << " - " << finalMessage << std::endl;
}
//This function uses CryptoPP's AutoSeededRandomPool and GenerateBlock() to generate cryptographically secure random integers
long long int genSecureInt()
{
    CryptoPP::AutoSeededRandomPool numGen;
    unsigned char theNum[4];
    numGen.GenerateBlock(theNum, 4);
    long long int secInt = *theNum;
    return secInt;   
}
//This function will perform a SHA-512 hash on the integer key passed in and return the hash as a hexadecimal string
std::string genHash(int secretKey)
{
    //Convert integer key to string
    std::string keyStr = std::to_string(secretKey);
    CryptoPP::byte const* keyData = (CryptoPP::byte*) keyStr.data();
    unsigned int keyDataLength = keyStr.size();
    CryptoPP::byte shaDigest[CryptoPP::SHA512::DIGESTSIZE];
    CryptoPP::SHA512().CalculateDigest(shaDigest, keyData, keyDataLength);
    //Now let's hex encode this SHA digest
    CryptoPP::HexEncoder enc;
    //Create string to hold this new hashed value encoded in its hexadecimal representation
    std::string keyOutput;
    enc.Attach(new CryptoPP::StringSink(keyOutput));
    enc.Put(shaDigest, sizeof(shaDigest));
    enc.MessageEnd();

    return keyOutput;
}

//This exp function will return the value of [(base^power) % prime]
long long exp(long long base, long long power, long long prime)
{
    long long resValue;
    if(power == 1)
    {
        return base;
    }
    resValue = exp(base, power/2, prime);
    if(power % 2 == 0)
    {
        return ((resValue * resValue)%prime);
    }
    else
    {
        return (((resValue * resValue) % prime)*base) % prime;
    }
}

//Diffie-Hellman key agreement function, bool serv is used to indicate if it's the server calling this func
int genKeys(int socket, bool serv)
{
    int secKey;
    long long int g = 9;
    //p is a large, safe prime that we can rely on for our calculations
    long long int p = 25959;
    
    if(serv == true)
    {
        //Generate secret int (server's private key)
        long long int a = genSecureInt();
        //Calculate server's public key: bigA = (g^a) % p
        int bigA = (int)exp(g, a, p);

        //Now send servers public key (bigA) to client
        std::string aString = std::to_string(bigA);
        char const *aSend = aString.c_str();
        write(socket, aSend, sizeof(aSend));

        //Receive client's public key (bigB) from the client
        char receivedFromB[32];
        int numBytesFromB = read(socket, receivedFromB, 32);
        char bNum[numBytesFromB];
        memcpy(bNum, receivedFromB, numBytesFromB);
        long long int numReceivedB = atoll(bNum);
        
        //Calculate the shared secret key secKey = (B^a) % p
        secKey = (int)exp(numReceivedB, a, p);
    }
    else if(serv == false)
    {
        //Generate secret int (client's private key)
        long long int b = genSecureInt();
        //Calculate client's public key: bigB = (g^b) % p
        int bigB = (int)exp(g, b, p);
        
        //Receive server's public key (bigA) from server
        char receivedBuffer[32];
        int numBytesFromA = read(socket, receivedBuffer, 32);
        char aNum[numBytesFromA];
        memcpy(aNum, receivedBuffer, numBytesFromA);
        long long int numReceivedA = atoll(aNum);
        
        //Now send client's public key (bigB) to server
        std::string bString = std::to_string(bigB);
        char const *bSend = bString.c_str();
        write(socket, bSend, sizeof(bSend));

        //Calculate the shared secret key: secKey = (A^b) % p
        secKey = (int)exp(numReceivedA, b, p);
    }
    return secKey;
}

//Perform AES-256 encryption on string message, given the key and IV, returning ciphertext string
std::string encryptMessage(std::string message, std::string keyHash, unsigned char IV[])
{   
    //First let's create the unsigned char[32] to hold our key for encryption
    unsigned char myKey[CryptoPP::AES::MAX_KEYLENGTH];
    //Set myKey to all 0s to eliminate garbage values
    memset(myKey, 0, CryptoPP::AES::MAX_KEYLENGTH);
    //Copy the key into myKey variable for encryption
    memcpy(myKey, keyHash.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
    
    std::string finalCipher;

    //Create the AES encryption object and pass the key and IV values to it
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbencrypt(myKey, 32, IV);
    //Perform Encryption, StringSink will push the encrypted text to the finalCipher string
    CryptoPP::StringSource cfbSS(message, true, new CryptoPP::StreamTransformationFilter(cfbencrypt, new CryptoPP::StringSink(finalCipher)));

    //Return the ciphertext string
    return finalCipher;
}

//Perform AES-256 decryption on string ciphertext, given the key and IV, returning plaintext string
std::string decryptMessage(std::string cipher, std::string keyHash, unsigned char IV[])
{
    //First let's create the unsigned char[32] to hold our key for decryption
    unsigned char myKeyD[CryptoPP::AES::MAX_KEYLENGTH];
    //Set myKeyD to all 0s to eliminate garbage values
    memset(myKeyD, 0, CryptoPP::AES::MAX_KEYLENGTH);
    //Now copy the key in c string form into the myKeyD variable
    memcpy(myKeyD, keyHash.c_str(), CryptoPP::AES::MAX_KEYLENGTH);

    std::string plainText;

    //Create the AES decryption object and pass the key and IV values to it
    CryptoPP::CFB_Mode <CryptoPP::AES>::Decryption cfbDecrypt(myKeyD, 32, IV);
    //Perform decryption - the StringSink will push the decrypted text to the plainText string
    CryptoPP::StringSource cfbSS(cipher, true, new CryptoPP::StreamTransformationFilter(cfbDecrypt, new CryptoPP::StringSink(plainText)));
    
    //Return the plaintext string
    return plainText;
}

   
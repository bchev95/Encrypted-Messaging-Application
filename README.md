## Overview
This project consists of an encrypted messaging application written in C++. It allows two users to communicate over TCP/IP sockets in a terminal, and send messages up to 140 characters long, which are encrypted with AES-256 CFB mode. The key agreement is performed through the Diffie-Hellman protocol, and the integers that represent the shared secret key returned by said protocol are put through a SHA-512 hash. The first 32 bytes (256 bits) of the hexadecimal representation of that hash value are used as the key for AES-256 encryption/decryption. IVs are randomly generated in a cryptographically secure way and attached to the end of the ciphertext when it is sent from sender to recipient.

## Installation Guide
The library used to provide encryption is Crypto++ (also known as CryptoPP), a free and open source C++ cryptography library. It is easily available on Github and on their website (https://www.cryptopp.com). I suggest pulling directly from the git repo as I’m about to demonstrate. My program requires version 8.2 of CryptoPP; to install the library on my Ubuntu machine, I ran the following:
1. cd Documents
2. git clone https://github.com/weidai11/cryptopp.git cryptopp
> This will create a folder called 'cryptopp' in the current directory
3. cd cryptopp
4. make
5. make test
> This just ensures that "make" ran successfully
6. sudo make install  
Once this has successfully installed, enter the directory where the project files are located and compile the program by typing "make". This will produce two executable ‘.o’ files, “server” and “client”.

## Running the Program
The server must be run first, as it binds to a port and listens for connections. Both server and client are run in the following style -
1. “./server [port number]”
> example: “./server 12000”
2. “./client [port number]”
> example: “./client 12000”

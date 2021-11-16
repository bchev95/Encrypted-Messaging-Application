#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "mutualFunctions.h"
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

AutoSeededRandomPool pseudoGen;

int main(int argc, char* argv[])
{
    //Call the checkParams function to ensure command line args are correctly formatted
    int checkVal = checkParams(argc, argv[1]);
    if(checkVal == -1)
    {
        std::cout << "Exiting program" << std::endl;
        return -1;
    }
    
    int bytesReceived;
    fd_set fdset;
    int numFileDescrip;
    int cmdLineNum = atoi(argv[1]);
    std::cout << "Hello there, initiating connection to port: " << cmdLineNum << std::endl;
           
    struct sockaddr_in serv_addr;
    bzero((char*) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(cmdLineNum);

    //Set up the socket to connect to server
    int cliSocket = socket(AF_INET, SOCK_STREAM, 0);
    //Attempt to initiate connection, clientConnect will return 0 if successful
    int clientConnect = connect(cliSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if(clientConnect < 0)
    {
        std::cout << "Error connecting to port " << cmdLineNum << std::endl;
        close(cliSocket);
        return -1;
    }
    else if(clientConnect == 0)
    {
        //Successfully connected, now must generate keys
        int k = genKeys(cliSocket, false);
        //Hash the key integer k
        std::string keyHash = genHash(k);
        //Take the first 32 bytes (256 bits) of this hash for use as our encryption/decryption key in AES-256
        keyHash = keyHash.substr(0,32);

        std::cout << "Client successfully connected to port: " << cmdLineNum << std::endl;
        //Create buffer to read from stdin/messages from socket as appropriate
        char messageBuffCli[512];
        
        while(true)
        {
            FD_ZERO(&fdset);
            FD_SET(STDIN_FILENO, &fdset);
            FD_SET(cliSocket, &fdset);
            numFileDescrip = std::max(STDIN_FILENO, cliSocket) +1;
            int selecVal = select(numFileDescrip, &fdset, NULL, NULL, NULL);
            if(selecVal == -1)
            {
                std::cout << "Error on select" << std::endl;
                close(cliSocket);
                return -1;
            }
            if(FD_ISSET(STDIN_FILENO, &fdset))
            {
                //Read what's in stdin into our buffer messageBuffCli
                bytesReceived = read(STDIN_FILENO, messageBuffCli, 512);
                //Create another buffer solely of size bytesReceived and copy in the contents of messageBuffCli
                char ourMessage[bytesReceived];
                memset(ourMessage, 0, bytesReceived);    
                memcpy(ourMessage, messageBuffCli, bytesReceived);
                //Convert ourMessage to a string to send to the encryptMessage() function
                std::string messageToSend(ourMessage);

                //Create new unsigned char[16] to hold IV, memset it to all 0s and then fill with securely generated random bytes
                unsigned char IV[CryptoPP::AES::BLOCKSIZE];
                memset(IV, 0,  sizeof(IV));
                pseudoGen.GenerateBlock(IV, CryptoPP::AES::BLOCKSIZE);
                
                //Perform encryption on the message with this IV and key
                std::string cipherTxt = encryptMessage(messageToSend, keyHash, IV);
                
                //Now we have to convert the string to char[] for sending
                //Create char array large enough to fit the ciphertext and IV
                char toSend[cipherTxt.size() + CryptoPP::AES::BLOCKSIZE];
                memset(toSend, 0, sizeof(toSend));
                //Fill toSend char array with ciphertext followed by IV
                for(int i = 0; i < cipherTxt.size(); i++)
                {
                    toSend[i] = cipherTxt[i];
                }
                int ivCounter = 0;
                for(int j = cipherTxt.size(); j < cipherTxt.size()+ 16; j++)
                {
                    toSend[j] = IV[ivCounter];
                    ivCounter++;
                }
                
                //Send ciphertext to other party
                write(cliSocket, toSend, sizeof(toSend));
                //Print the message to sender as well
                printMessage(ourMessage, "(You) ");
                messageToSend.clear();             
            }
            if(FD_ISSET(cliSocket, &fdset))
            {
                //Zero out our buffer before reading in the message we received
                memset(messageBuffCli, 0, sizeof(messageBuffCli));
                
                bytesReceived = read(cliSocket, messageBuffCli, 512);      
                
                if(bytesReceived == 0 || bytesReceived == -1)
                {             
                    //If bytesReceived is 0 or -1, then the connection was terminated. Close the socket and exit
                    close(cliSocket);
                    break;
                }
                    
                //First let's read the receivedIV from the socket (we know it will be the last 16 bytes in the buffer)
                unsigned char receivedIV[CryptoPP::AES::BLOCKSIZE];
                memset(receivedIV, 0, CryptoPP::AES::BLOCKSIZE);
                int ivStart = bytesReceived-16;
                int ivCounter = ivStart;
                //Populate the receivedIV and receivedCipher variables from the buffer 
                for(int i = 0; i < 16; i++)
                {
                    receivedIV[i] = messageBuffCli[ivCounter];
                    ivCounter++;
                }
                char receivedCipher[bytesReceived-16];
                for(int j = 0; j < ivStart; j++)
                {
                    receivedCipher[j] = messageBuffCli[j];
                }
                //Convert receivedCipher char[] to string to be passed to decrypt function
                std::string cipherMessage(receivedCipher);
                
                //Perform decryption with our key and the ciphertext and IV we received
                std::string plainMessage = decryptMessage(cipherMessage, keyHash, receivedIV);
                //Print the decrypted message to client
                printMessage(plainMessage, "Server");
            }
        }
    }
    return 0;
}
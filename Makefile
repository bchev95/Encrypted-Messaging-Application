all:    server  client
server:	server.cpp	mutualFunctions.h
	g++ -o	server	server.cpp	-lcryptopp
client: client.cpp	mutualFunctions.h
	g++	-o	client	client.cpp	-lcryptopp

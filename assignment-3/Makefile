CXX = g++
CXXFLAGS = -std=c++17 -g -I. -lgmp # -Weverything

SRCS = server.cpp client.cpp 
LIBS = crypto/rsa.hpp crypto/aes.hpp socket/httpmessage.cpp socket/simplesocket.cpp socket/simplesocket.h socket/serversocket.h socket/clientsocket.h socket/httpmessage.h

all: client server

client: client.cpp $(LIBS)
	$(CXX) client.cpp socket/simplesocket.cpp -o client $(CXXFLAGS)

server: server.cpp $(LIBS)
	$(CXX) server.cpp socket/simplesocket.cpp -o server -lpthread $(CXXFLAGS)

clean:
	rm -f server client

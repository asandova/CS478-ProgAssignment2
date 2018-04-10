all: link

link:   main.o BinaryString.o des_utils.o DES.o
        g++ main.o BinaryString.o des_utils.o DES.o -o des

main.o: main.cpp
        g++ -c main.cpp

BinaryString.o: BinaryString.h BinaryString.cpp
        g++ -c BinaryString.cpp

des_utils.o: des_utils.h des_utils.cpp
        g++ -c des_utils.cpp

DES.o: DES.h DES.cpp des_utils.h
        g++ -c DES.cpp

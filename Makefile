all: des

des:
	g++ -I/opt/halon/include/ -I/usr/local/include/ -fPIC -shared des.cpp -lcrypt -o des.so

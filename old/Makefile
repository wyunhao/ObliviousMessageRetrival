all:
	g++ -g -O2 -std=c++17 -pthread -march=native transac.cpp -o transac2 -lntl -lgmp -lm

SHELL = /bin/bash
CXX = g++ 
#DEPS := utils.h
SRCS := tfhe_bfv_tst.cpp
OBJS := $(SRCS:.cpp=.o)
IDIR := ./seallib/include/SEAL-3.6/
CFLAGS = --std=c++17 -I $(IDIR)
LDFLAGS := ./seallib/lib/libseal-3.6.a -lpthread -lntl -ltfhe-spqlios-fma 

.PHONY: clean tstmain all

testBFVTFHE: 
	make tstmain

tstmain: tfhe_bfv_tst.o $(DEPS)
	$(CXX) -o $@ $< $(LDFLAGS)
	rm *.o

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $^

clean:
	rm -f tstmain

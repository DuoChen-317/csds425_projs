proj1: proj1.o
	g++ -o proj1 proj1.o

proj1.o: proj1.cpp
	g++ -c -g -Wall proj1.cpp

clean:
	rm -f *.o
	rm -f proj1e

all: main 

main: main.c cacheutils.h
	gcc main.c -Os -o main -pthread -march=native
	
clean:
	rm -f main 
	

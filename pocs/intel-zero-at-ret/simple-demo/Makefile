all: vtable dataidx-accessbit dataidx-float

vtable: vtable.c cacheutils.h
	gcc vtable.c -Os -o vtable -march=native -ggdb

dataidx-accessbit: dataidx-accessbit.c cacheutils.h
	gcc dataidx-accessbit.c -Os -o dataidx-accessbit -march=native -ggdb

dataidx-float: dataidx-float.c cacheutils.h
	gcc dataidx-float.c -Os -o dataidx-float -march=native -ggdb
	
clean:
	rm -f vtable dataidx-accessbit dataidx-float
	

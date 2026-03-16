all: attacker victim

attacker: attacker.c cacheutils.h
	gcc attacker.c -Os -o attacker -pthread -march=native

victim: victim.c cacheutils.h
	gcc victim.c -Os -o victim -pthread -march=native
	
clean:
	rm -f attacker victim
	

all: dns-sequential dns-mutex dns-rw dns-fine

CFLAGS = -g -Wall -Werror -pthread

%.o: %.c *.h
	gcc $(CFLAGS) -c -o $@ $<

dns-sequential: main.c sequential-trie.o
	gcc $(CFLAGS) -o dns-sequential sequential-trie.o main.c

dns-mutex: main.c mutex-trie.o
	gcc $(CFLAGS) -o dns-mutex mutex-trie.o main.c

dns-rw: main.c rw-trie.o
	gcc $(CFLAGS) -o dns-rw rw-trie.o main.c

dns-fine: main.c fine-trie.o
	gcc $(CFLAGS) -o dns-fine fine-trie.o main.c

clean:
	rm -f *~ *.o dns-sequential dns-mutex dns-rw dns-fine

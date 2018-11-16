all:
	gcc -Werror -D_DEBUG -g wow.c

clean:
	rm -f a.out *~

all:
	gcc -Werror -D_DEBUG -g wow.c -o wow
clean:
	rm -f wow *~

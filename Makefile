all: sock_example.c
	gcc -o sock_example sock_example.c <path to libbpf.a> -lelf

clean:
	rm sock_example

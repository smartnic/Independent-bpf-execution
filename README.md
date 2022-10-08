Steps to run sock_example.c:
1) Input.txt should contain the code to insert in the 'struct bpf_insn prog []' of sock_example.c. This is the main bpf program. Currently Input.txt contains what was there in the struct for the original sock_example.c.
2) In the Makefile make sure to change <path to libbpf.a> to the path, on your machine, of the libbpf.a file in this folder.
3) To compile: "make"
4) To run and get results: "sudo ./sock_example"
5) "make clean"

Note: In order to get verifier error log for unsafe programs you can uncomment line 57 in sock_example.c.

Information about machine where this code executed:
OS Name: Ubuntu 20.04.3 LTS
OS Type: 64-bit
Kernel release version: 5.11.0-44-generic

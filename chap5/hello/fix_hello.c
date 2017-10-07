#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#define SIZE 0x30
#define JNE_OPCODE 0x75

unsigned char nop_code[] =
	"\x90\x90";

int main(int argc, char **argv) {
	int i, offset;
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;
	struct nlist nl[] = { {NULL}, {NULL}, };
	unsigned char hello_code[SIZE];

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "hello";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found\n",
				nl[0].n_name);
		exit(-1);
	}

	if (kvm_read(kd, nl[0].n_value, hello_code, SIZE) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	for (i=0;i < SIZE;i++) {
		if (hello_code[i] == JNE_OPCODE) {
			offset = i;
			break;
		}
	}

	if (kvm_write(kd, nl[0].n_value + offset
				, nop_code
				, sizeof(nop_code) - 1) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	exit(0);
}

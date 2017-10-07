#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/sysproto.h>

static int
hello(struct thread *td, void *syscall_args) {
	int i;
#pragma clang loop unroll(disable)
	for (i=0;i<10;i++)
		printf("FreeBSD Rock!\n");
	return (0);
}

static struct sysent hello_sysent = {
	0,       /* number of arguments */
	hello    /* implementing function */
};

static int offset = NO_SYSCALL;

static int
load(struct module *module, int cmd, void *arg) {
	int error = 0;
	
	switch (cmd) {
		case MOD_LOAD:
			uprintf("System call loaded at offset %d.\n", offset);
			break;

		case MOD_UNLOAD:
			uprintf("Systemm call unloaded from offset %d.\n", offset);
			break;

		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

SYSCALL_MODULE(hello, &offset, &hello_sysent, load, NULL);

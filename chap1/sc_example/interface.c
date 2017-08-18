#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>

#include <errno.h>
#include <sys/param.h>
#include <sys/linker.h>

int
main(int argc, char *argv[])
{
	int syscall_num;
	struct module_stat stat;

	if (argc != 2) {
		printf("Usage:\n%s <string>\n", argv[0]);
		exit(0);
	}

	stat.version = sizeof(stat);
	int mod_id = modfind("sys/sc_example");

	if (errno != 0) {
		perror(NULL);
		exit(0);
	}

	modstat(mod_id, &stat);
	syscall_num = stat.data.intval;

	return (syscall(syscall_num, argv[1]));
}

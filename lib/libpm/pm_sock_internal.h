

#ifndef PM_SOCK_INTERNAL_H_
#define PM_SOCK_INTERNAL_H_

#include "pm_sock.h"
#include <linux/if_ether.h> // ETH_ALEN

#ifdef __cplusplus
extern "C" {
#endif


struct pm_instance {
    struct pm_params params;
    struct {
        int i_ifindex;
        struct sockaddr_in local_adr;
        struct sockaddr_in6 local_adr6;        
        // struct sockaddr_in gw_adr;
        // struct sockaddr_in6 gw_adr6;
        unsigned char local_mac[ETH_ALEN+2];
        unsigned char gw_mac[ETH_ALEN+2];
    } opt;
};

/*
 * Socket state bits.
 *
 * Historically, this bits were all kept in the so_state field.  For
 * locking reasons, they are now in multiple fields, as they are
 * locked differently.  so_state maintains basic socket state protected
 * by the socket lock.  so_qstate holds information about the socket
 * accept queues.  Each socket buffer also has a state field holding
 * information relevant to that socket buffer (can't send, rcv).  Many
 * fields will be read without locks to improve performance and avoid
 * lock order issues.  However, this approach must be used with caution.
 */
#define	PM_SS_NOFDREF		0x0001	/* no file table ref any more */
#define	PM_SS_ISCONNECTED		0x0002	/* socket connected to a peer */
#define	PM_SS_ISCONNECTING		0x0004	/* in process of connecting to peer */
#define	PM_SS_ISDISCONNECTING	0x0008	/* in process of disconnecting */
#define	PM_SS_NBIO			0x0100	/* non-blocking ops */
#define	PM_SS_ASYNC		0x0200	/* async i/o notify */
#define	PM_SS_ISCONFIRMING		0x0400	/* deciding to accept connection req */
#define	PM_SS_ISDISCONNECTED	0x2000	/* socket disconnected from peer */

/*
 * Protocols can mark a socket as SS_PROTOREF to indicate that, following
 * pru_detach, they still want the socket to persist, and will free it
 * themselves when they are done.  Protocols should only ever call sofree()
 * following setting this flag in pru_detach(), and never otherwise, as
 * sofree() bypasses socket reference counting.
 */
#define	PM_SS_PROTOREF		0x4000	/* strong protocol reference */


struct pm_protosw {
	short	pr_type;		/* socket type used for */
	// struct	domain *pr_domain;	/* domain protocol a member of */
	short	pr_protocol;		/* protocol number */
	short	pr_flags;		/* see below */
/* protocol-protocol hooks */
	// pr_input_t *pr_input;		/* input to protocol (from below) */
	// pr_output_t *pr_output;		/* output to protocol (from above) */
	// pr_ctlinput_t *pr_ctlinput;	/* control input (from below) */
	// pr_ctloutput_t *pr_ctloutput;	/* control output (from above) */
/* utility hooks */
	// pr_init_t *pr_init;
	// pr_destroy_t *pr_destroy;
	// pr_fasttimo_t *pr_fasttimo;	/* fast timeout (200ms) */
	// pr_slowtimo_t *pr_slowtimo;	/* slow timeout (500ms) */
	// pr_drain_t *pr_drain;		/* flush any excess space possible */

	// struct	pr_usrreqs *pr_usrreqs;	/* user-protocol hook */
};
/*#endif*/

// #define	PM_PR_SLOWHZ	2		/* 2 slow timeouts per second */
// #define	PM_PR_FASTHZ	5		/* 5 fast timeouts per second */

/*
 * This number should be defined again within each protocol family to avoid
 * confusion.
 */
// #define	PM_PROTO_SPACER	32767		/* spacer for loadable protocols */

/*
 * Values for pr_flags.
 * PR_ADDR requires PR_ATOMIC;
 * PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
 * PR_IMPLOPCL means that the protocol allows sendto without prior connect,
 *	and the protocol understands the MSG_EOF flag.  The first property is
 *	is only relevant if PR_CONNREQUIRED is set (otherwise sendto is allowed
 *	anyhow).
 */
#define	PM_PR_ATOMIC	0x01		/* exchange atomic messages only */
#define	PM_PR_ADDR		0x02		/* addresses given with messages */
#define	PM_PR_CONNREQUIRED	0x04		/* connection required by protocol */
#define	PM_PR_WANTRCVD	0x08		/* want PRU_RCVD calls */
#define	PM_PR_RIGHTS	0x10		/* passes capabilities */
#define PM_PR_IMPLOPCL	0x20		/* implied open/close */
#define	PM_PR_LASTHDR	0x40		/* enforce ipsec policy; last header */

struct pm_socket {
    struct pm_instance* inst;
    int fd;

	struct pm_so_info info;

    int so_error;
    int so_state; // eg: PM_SS_ISCONNECTED,...
    int so_options; // eg: SO_ACCEPTCONN,...
    struct pm_protosw so_proto;
    
    unsigned int tp_rblock_num;
    unsigned int tp_wblock_num;
    struct iovec* tp_rd;
    struct iovec* tp_wd;
    uint8_t* tp_map;
    size_t tp_map_size;
};

void pm_close_fd(int fd);

#define pm_err() (errno)
const char* pm_err_msg(int e);

#ifdef __cplusplus
}
#endif

#endif

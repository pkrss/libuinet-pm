/*-
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)socketvar.h	8.3 (Berkeley) 2/19/95
 *
 * $FreeBSD: release/9.1.0/sys/sys/socketvar.h 215178 2010-11-12 13:02:26Z luigi $
 */

#ifndef _SYS_SOCKETVAR_H_
#define _SYS_SOCKETVAR_H_

#ifdef _KERNEL
#include "opt_passiveinet.h"
#endif

#include <sys/queue.h>			/* for TAILQ macros */
#include <sys/selinfo.h>		/* for struct selinfo */
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_sx.h>
#include <sys/sockbuf.h>
#include <sys/sockstate.h>
#ifdef _KERNEL
#include <sys/sockopt.h>

#include <net/vnet.h>
#endif

struct vnet;

struct in_l2info;

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
typedef	u_quad_t so_gen_t;

struct socket;

/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by SOCK_LOCK(so).
 * (c) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (d) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by ACCEPT_LOCK().
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 */
struct socket {
	int	so_count;		/* (b) reference count */
	short	so_type;		/* (a) generic type, see socket.h */
	int	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* (b) internal state flags SS_* */
	int	so_qstate;		/* (e) internal state flags SQ_* */
	void	*so_pcb;		/* protocol control block */
	struct	vnet *so_vnet;		/* network stack instance */
	struct	protosw *so_proto;	/* (a) protocol handle */
/*
 * Variables for connection queuing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_incomp queues partially completed connections,
 * while so_comp is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_incomp or so_comp.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	socket *so_head;	/* (e) back pointer to listen socket */
	TAILQ_HEAD(, socket) so_incomp;	/* (e) queue of partial unaccepted connections */
	TAILQ_HEAD(, socket) so_comp;	/* (e) queue of complete unaccepted connections */
	TAILQ_ENTRY(socket) so_list;	/* (e) list of unaccepted connections */
	u_short	so_qlen;		/* (e) number of unaccepted connections */
	u_short	so_incqlen;		/* (e) number of unaccepted incomplete
					   connections */
	u_short	so_qlimit;		/* (e) max number queued connections */
	short	so_timeo;		/* (g) connection timeout */
	u_short	so_error;		/* (f) error affecting connection */
	struct	sigio *so_sigio;	/* [sg] information for async I/O or
					   out of band data (SIGURG) */
	u_long	so_oobmark;		/* (c) chars to oob mark */
	TAILQ_HEAD(, aiocblist) so_aiojobq; /* AIO ops waiting on socket */

	struct sockbuf so_rcv, so_snd;

	struct	ucred *so_cred;		/* (a) user credentials */
	struct	label *so_label;	/* (b) MAC label for socket */
	struct	label *so_peerlabel;	/* (b) cached MAC label for peer */
	/* NB: generation count must not be first. */
	so_gen_t so_gencnt;		/* (h) generation count */
	void	*so_emuldata;		/* (b) private data for emulators */
 	struct so_accf {
		struct	accept_filter *so_accept_filter;
		void	*so_accept_filter_arg;	/* saved filter args */
		char	*so_accept_filter_str;	/* saved user args */
	} *so_accf;
	/*
	 * so_fibnum, so_user_cookie and friends can be used to attach
	 * some user-specified metadata to a socket, which then can be
	 * used by the kernel for various actions.
	 * so_user_cookie is used by ipfw/dummynet.
	 */
	int so_fibnum;		/* routing domain for this socket */
	uint32_t so_user_cookie;

	struct so_upcallprep {
		void (*soup_accept)(struct socket *so, void *arg);
		void *soup_accept_arg;
		void (*soup_receive)(struct socket *so, void *arg, int64_t, int64_t);
		void *soup_receive_arg;
		void (*soup_send)(struct socket *so, void *arg, int64_t);
		void *soup_send_arg;
	} so_upcallprep;		/* (a) initialized once immediately after socket creation */ 

	struct in_l2info *so_l2info;	/* (b) PROMISCUOUS_INET L2 info */
	unsigned int so_user_ctx_count; /* (b) number of user contexts in use, lock needed to increment */
#define SOMAXUSERCTX 1
	void *so_user_ctx[SOMAXUSERCTX]; /* (a) each pointer managed by user */
	struct socket *so_passive_peer;	/* (a) peer socket when performing passive reassembly */

	struct mbuf_pm_opt* pm_opt; // our opt arg
};


#ifdef _KERNEL

/*
 * Global accept mutex to serialize access to accept queues and
 * fields associated with multiple sockets.  This allows us to
 * avoid defining a lock order between listen and accept sockets
 * until such time as it proves to be a good idea.
 */
VNET_DECLARE(struct mtx, accept_mtx);
#define V_accept_mtx	VNET(accept_mtx)

#define ACCEPT_LOCK_INIT()					\
	VNET_MTX_INIT(&V_accept_mtx, "accept", NULL, MTX_DEF)
#define ACCEPT_LOCK_DESTROY()		VNET_MTX_DESTROY(&V_accept_mtx)
#define	ACCEPT_LOCK_ASSERT()		VNET_MTX_ASSERT(&V_accept_mtx, MA_OWNED)
#define	ACCEPT_UNLOCK_ASSERT()		VNET_MTX_ASSERT(&V_accept_mtx, MA_NOTOWNED)
#define	ACCEPT_LOCK()			VNET_MTX_LOCK(&V_accept_mtx)
#define	ACCEPT_UNLOCK()			VNET_MTX_UNLOCK(&V_accept_mtx)

/*
 * Per-socket mutex: we reuse the receive socket buffer mutex for space
 * efficiency.  This decision should probably be revisited as we optimize
 * locking for the socket code.
 */
#define	SOCK_MTX(_so)			SOCKBUF_MTX(&(_so)->so_rcv)
#define	SOCK_LOCK(_so)			SOCKBUF_LOCK(&(_so)->so_rcv)
#define	SOCK_OWNED(_so)			SOCKBUF_OWNED(&(_so)->so_rcv)
#define	SOCK_UNLOCK(_so)		SOCKBUF_UNLOCK(&(_so)->so_rcv)
#define	SOCK_LOCK_ASSERT(_so)		SOCKBUF_LOCK_ASSERT(&(_so)->so_rcv)

#endif

/*
 * Socket state bits stored in so_qstate.
 */
#define	SQ_INCOMP		0x0800	/* unaccepted, incomplete connection */
#define	SQ_COMP			0x1000	/* unaccepted, complete connection */

/*
 * Externalized form of struct socket used by the sysctl(3) interface.
 */
struct xsocket {
	size_t	xso_len;	/* length of this structure */
	struct	socket *xso_so;	/* makes a convenient handle sometimes */
	short	so_type;
	int	so_options;
	short	so_linger;
	short	so_state;
	caddr_t	so_pcb;		/* another convenient handle */
	int	xso_protocol;
	int	xso_family;
	u_short	so_qlen;
	u_short	so_incqlen;
	u_short	so_qlimit;
	short	so_timeo;
	u_short	so_error;
	pid_t	so_pgid;
	u_long	so_oobmark;
	struct xsockbuf so_rcv, so_snd;
	uid_t	so_uid;		/* XXX */
};

#ifdef _KERNEL

/*
 * Macros for sockets and socket buffering.
 */

/*
 * Flags to sblock().
 */
#define	SBL_WAIT	0x00000001	/* Wait if not immediately available. */
#define	SBL_NOINTR	0x00000002	/* Force non-interruptible sleep. */
#define	SBL_VALID	(SBL_WAIT | SBL_NOINTR)

/*
 * Do we need to notify the other side when I/O is possible?
 */
#define	sb_notify(sb)	(((sb)->sb_flags & (SB_WAIT | SB_SEL | SB_ASYNC | \
    SB_UPCALL | SB_AIO | SB_KNOTE)) != 0)

/* do we have to send all at once on a socket? */
#define	sosendallatonce(so) \
    ((so)->so_proto->pr_flags & PR_ATOMIC)

/* can we read something from so? */
#define	soreadabledata(so) \
    ((so)->so_rcv.sb_cc >= (so)->so_rcv.sb_lowat || \
	!TAILQ_EMPTY(&(so)->so_comp) || (so)->so_error)
#define	soreadable(so) \
	(soreadabledata(so) || ((so)->so_rcv.sb_state & SBS_CANTRCVMORE))

/* can we write something to so? */
#define	sowriteable(so) \
    ((sbspace(&(so)->so_snd) >= (so)->so_snd.sb_lowat && \
	(((so)->so_state&SS_ISCONNECTED) || \
	  ((so)->so_proto->pr_flags&PR_CONNREQUIRED)==0)) || \
     ((so)->so_snd.sb_state & SBS_CANTSENDMORE) || \
     (so)->so_error)

/*
 * soref()/sorele() ref-count the socket structure.  Note that you must
 * still explicitly close the socket, but the last ref count will free
 * the structure.
 */
#define	soref(so) do {							\
	SOCK_LOCK_ASSERT(so);						\
	++(so)->so_count;						\
} while (0)

#ifdef PASSIVE_INET

extern void in_passive_release_sock_locks(struct socket *so);

#define	sorele(so) do {							\
	ACCEPT_LOCK_ASSERT();						\
	SOCK_LOCK_ASSERT(so);						\
	if ((so)->so_passive_peer)					\
		SOCK_LOCK_ASSERT((so)->so_passive_peer);		\
	if ((so)->so_count <= 0)					\
		panic("sorele");					\
	if (--(so)->so_count == 0)					\
		sofree(so);						\
	else {								\
		if ((so)->so_passive_peer)				\
			in_passive_release_sock_locks(so);		\
		else							\
			SOCK_UNLOCK(so);				\
		ACCEPT_UNLOCK();					\
	}								\
} while (0)
#else
#define	sorele(so) do {							\
	ACCEPT_LOCK_ASSERT();						\
	SOCK_LOCK_ASSERT(so);						\
	if ((so)->so_count <= 0)					\
		panic("sorele");					\
	if (--(so)->so_count == 0)					\
		sofree(so);						\
	else {								\
		SOCK_UNLOCK(so);					\
		ACCEPT_UNLOCK();					\
	}								\
} while (0)
#endif


/*
 * In sorwakeup() and sowwakeup(), acquire the socket buffer lock to
 * avoid a non-atomic test-and-wakeup.  However, sowakeup is
 * responsible for releasing the lock if it is called.  We unlock only
 * if we don't call into sowakeup.  If any code is introduced that
 * directly invokes the underlying sowakeup() primitives, it must
 * maintain the same semantics.
 */
#define	sorwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_rcv);				\
	if (sb_notify(&(so)->so_rcv))					\
		sowakeup((so), &(so)->so_rcv);	 			\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_rcv);				\
} while (0)

#define	sorwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_rcv);					\
	sorwakeup_locked(so);						\
} while (0)

#define	sowwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_snd);				\
	if (sb_notify(&(so)->so_snd))					\
		sowakeup((so), &(so)->so_snd); 				\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_snd);				\
} while (0)

#define	sowwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_snd);					\
	sowwakeup_locked(so);						\
} while (0)

struct accept_filter {
	char	accf_name[16];
	int	(*accf_callback)
		(struct socket *so, void *arg, int waitflag);
	void *	(*accf_create)
		(struct socket *so, char *arg);
	void	(*accf_destroy)
		(struct socket *so);
	SLIST_ENTRY(accept_filter) accf_next;
};

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_ACCF);
MALLOC_DECLARE(M_PCB);
MALLOC_DECLARE(M_SONAME);
#endif

VNET_DECLARE(int, numopensockets);
#define V_numopensockets	VNET(numopensockets)

VNET_DECLARE(so_gen_t, so_gencnt);
#define V_so_gencnt		VNET(so_gencnt)

extern int	maxsockets;
extern u_long	sb_max;
extern struct uma_zone *socket_zone;
extern so_gen_t so_gencnt;

struct mbuf;
struct sockaddr;
struct ucred;
struct uio;

/* 'which' values for socket upcalls. */
#define	SO_RCV		1
#define	SO_SND		2

/* Return values for socket upcalls. */
#define	SU_OK		0
#define	SU_ISCONNECTED	1

/*
 * From uipc_socket and friends
 */
int	sockargs(struct mbuf **mp, caddr_t buf, int buflen, int type);
int	getsockaddr(struct sockaddr **namp, caddr_t uaddr, size_t len);
void	soabort(struct socket *so);
int	soaccept(struct socket *so, struct sockaddr **nam);
int	socheckuid(struct socket *so, uid_t uid);
int	sobind(struct socket *so, struct sockaddr *nam, struct thread *td);
int	soclose(struct socket *so);
int	soconnect(struct socket *so, struct sockaddr *nam, struct thread *td);
int	soconnect2(struct socket *so1, struct socket *so2);
int	socow_setup(struct mbuf *m0, struct uio *uio);
#ifdef UINET
int	socreate(int dom, struct socket **aso, int type, int proto,
	    struct ucred *cred, struct thread *td, struct vnet *vnet);
#else
int	socreate(int dom, struct socket **aso, int type, int proto,
	    struct ucred *cred, struct thread *td);
#endif
int	sodisconnect(struct socket *so);
struct	sockaddr *sodupsockaddr(const struct sockaddr *sa, int mflags);
void	sofree(struct socket *so);
void	sohasoutofband(struct socket *so);
int	solisten(struct socket *so, int backlog, struct thread *td);
void	solisten_proto(struct socket *so, int backlog);
int	solisten_proto_check(struct socket *so);
struct socket *
	sonewconn(struct socket *head, int connstatus);
struct socket *
	sonewconn_passive_client(struct socket *head, int connstatus);

int	sopoll(struct socket *so, int events, struct ucred *active_cred,
	    struct thread *td);
int	sopoll_generic(struct socket *so, int events,
	    struct ucred *active_cred, struct thread *td);
int	soreceive(struct socket *so, struct sockaddr **paddr, struct uio *uio,
	    struct mbuf **mp0, struct mbuf **controlp, int *flagsp);
int	soreceive_stream(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreceive_dgram(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreceive_generic(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreserve(struct socket *so, u_long sndcc, u_long rcvcc);
void	sorflush(struct socket *so);
int	sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	    struct mbuf *top, struct mbuf *control, int flags,
	    struct thread *td);
int	sosend_dgram(struct socket *so, struct sockaddr *addr,
	    struct uio *uio, struct mbuf *top, struct mbuf *control,
	    int flags, struct thread *td);
int	sosend_generic(struct socket *so, struct sockaddr *addr,
	    struct uio *uio, struct mbuf *top, struct mbuf *control,
	    int flags, struct thread *td);
int	soshutdown(struct socket *so, int how);
void	sotoxsocket(struct socket *so, struct xsocket *xso);
void	soupcall_clear(struct socket *so, int which);
void	soupcall_set(struct socket *so, int which,
	    int (*func)(struct socket *, void *, int), void *arg);
int	souserctx_alloc(struct socket *so);
void	sowakeup(struct socket *so, struct sockbuf *sb);
int	selsocket(struct socket *so, int events, struct timeval *tv,
	    struct thread *td);

/*
 * Accept filter functions (duh).
 */
int	accept_filt_add(struct accept_filter *filt);
int	accept_filt_del(char *name);
struct	accept_filter *accept_filt_get(char *name);
#ifdef ACCEPT_FILTER_MOD
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_accf);
#endif
int	accept_filt_generic_mod_event(module_t mod, int event, void *data);
#endif

#endif /* _KERNEL */

#endif /* !_SYS_SOCKETVAR_H_ */

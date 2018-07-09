/*DiLiver Unicorn 2018 CopyLeft NothingRights. */
/*Ver1.3 Master Graduate Vertion 2018/JUY/07 */

#ifndef __aodvIot_h__
#define __aodvIot_h__

//#include <agent.h>
//#include <packet.h>
//#include <sys/types.h>
//#include <cmu/list.h>
//#include <scheduler.h>

#include <cmu-trace.h>
#include <priqueue.h>
#include <aodvIot/aodvIot_rtable.h>
#include <aodvIot/aodvIot_rqueue.h>
#include <classifier/classifier-port.h>

/** Function ON/OFF switch. **/


	#define AODViot_LOCAL_REPAIR
	// Allows local repair of routes	//this shit is a fake! X rosh 2018

	#define AODViot_LINK_LAYER_DETECTION //IF YOU TURN OFF THIS AODV WILL CRASH!!
	// Allows AODViot to use link-layer ( 802.11 ) feedback in determining when links are up/down.

	#define AODViot_USE_LL_METRIC
	/*Causes AODViot to apply a "smoothing" function to the link layer feedback that is generated
	by 802.11.In essence, it requires that RT_MAX_ERROR errors occurs within a window of
	RT_MAX_ERROR_TIME before the link is considered bad.*/

	// #define AODViot_USE_GOD_FEEDBACK
	  /* 我真TMD的不知道這哪裡神了...*/
	
	// #define RREQ_ID
	  /* the original AODV mechanism of prevent RREQ unlimited loop. */
	  /* WARNING if this function turns on the "Dynamic Route Table Update" WILL BE OFF!
	    AND "RREQ_Rebroadcast" function MUST TURN OFF manually.*/

	#define RREQ_Rebroadcast	//RREQ Rebroadcast
	  /* this is the new function that hear The RREQ it self ,if the node did not heard RREQ it will
	    Rebroadcast RREQ again. */

	#define RANDOM_FUNCTION
	  /* real random,use uncomment to turn on or off function ,so you won't need to change the code. */

/** Helper Function **/	
	
	// #define DEBUG
	// #define DEBUGSTATE
	// #define ERROR
	// #define ShowAODViot_Packet
	  /* show AODViot control packets by printf */
	// #define Show_Packet_detail //sub function of ShowAODViot_Packet
	  /* show AODViot control packets detail entry by printf */

#ifdef ShowAODViot_Packet
	// #define ShowAODViot_Packet_RREQ_Send
	// #define ShowAODViot_Packet_RREQ_Recv

	// #define ShowAODViot_Packet_RREP_Send
	// #define ShowAODViot_Packet_RREP_Recv

	// #define ShowAODViot_Packet_RERR_Send
	// #define ShowAODViot_Packet_RERR_Recv

	// #define ShowAODViot_Packet_RREP_ACK_Send
	// #define ShowAODViot_Packet_RREP_ACK_Recv
#endif

#define max( a,b )	( ( a ) > ( b ) ? ( a ) : ( b ) )
#define CURRENT_TIME	Scheduler::instance().clock()

/* ifdef */
	#ifdef RANDOM_FUNCTION
	#define RANDOM Random::seed_heuristically()
	#else
	#define RANDOM 1;//do nothing.
	#endif


	#ifdef DEBUG
	static int route_request = 0;
	#endif


	#ifdef ShowAODViot_Packet
	#define RED "\x1b[;31;7m"
	#define BLU "\x1b[;34;7m"
	#define YEL "\x1b[;33;7m"
	#define GRN "\x1b[;32;7m"
	#define RST "\x1b[0;m"
	#endif

class AODViot;

#define MY_ROUTE_TIMEOUT		10	 // 100 seconds
#define ACTIVE_ROUTE_TIMEOUT	10	 // 50 seconds
#define REV_ROUTE_LIFE			 6	 // 5	seconds
#define BCAST_ID_SAVE			6	 // 3 seconds

#define FREQUENCY 0.5 // sec
/* RouteCacheTimer :This is the interval of time to delete routecache*/

#define RREP_ACK_WAIT_TIME 0.1
#define RREP_ACK_RETRIES 3

#define RREQ_REBROADCAST_INTERVAL 0.09
#define RREQ_REBROADCAST_RETRIES 3

// No. of times to do network-wide search before timing out for
// MAX_RREQ_TIMEOUT sec.
#define RREQ_RETRIES		3
// timeout after doing network-wide search RREQ_RETRIES times
#define MAX_RREQ_TIMEOUT	10.0 //sec

/* Various constants used for the expanding ring search */
#define TTL_START	 5
#define TTL_THRESHOLD 7
#define TTL_INCREMENT 2

// This should be somewhat related to arp timeout
#define NODE_TRAVERSAL_TIME	 0.03		 // 30 ms
#define LOCAL_REPAIR_WAIT_TIME	0.15 //sec

// Should be set by the user using best guess ( conservative )
#define NETWORK_DIAMETER	30		 // 30 hops

// Must be larger than the time difference between a node propagates a route
// request and gets the route reply back.

//#define RREP_WAIT_TIME	 ( 3 * NODE_TRAVERSAL_TIME * NETWORK_DIAMETER ) // ms
//#define RREP_WAIT_TIME	 ( 2 * REV_ROUTE_LIFE )	// seconds
#define RREP_WAIT_TIME	 1.0	// sec

#define ID_NOT_FOUND	0x00
#define ID_FOUND	0x01
//#define INFINITY	0xff

// The followings are used for the forward() function. Controls pacing.
#define DELAY 1.0		 // random delay
#define NO_DELAY -1.0	 // no delay

// think it should be 30 ms
#define ARP_DELAY 0.01	// fixed delay to keep arp happy


#define HELLO_INTERVAL		1		 // 1000 ms
#define ALLOWED_HELLO_LOSS	3		 // packets
#define BAD_LINK_LIFETIME	 3		 // 3000 ms
#define MaxHelloInterval	( 1.25 * HELLO_INTERVAL )
#define MinHelloInterval	( 0.75 * HELLO_INTERVAL )

/* Timers */
class IotBroadcastTimer : public Handler {
	public:
		IotBroadcastTimer( AODViot* a ) : agent( a ) {}
		void	handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};

class IotHelloTimer : public Handler {
	public:
		IotHelloTimer( AODViot* a ) : agent( a ) {}
		void	handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};

class IotNeighborTimer : public Handler {
	public:
		IotNeighborTimer( AODViot* a ) : agent( a ) {}
		void	handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};

class IotRouteCacheTimer : public Handler {
	public:
		IotRouteCacheTimer( AODViot* a ) : agent( a ) {}
		void	handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};

class IotLocalRepairTimer : public Handler {
public:
	IotLocalRepairTimer( AODViot* a ) : agent( a ) {}
	void	handle( Event* );
private:
	AODViot	*agent;
	Event	intr;
};

class IotACKTimer : public Handler {
	public:
		IotACKTimer( AODViot* a ) : agent( a ) {}
		void handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};

class IotRREQreBroadcastTimer : public Handler {
	public:
		IotRREQreBroadcastTimer( AODViot* a ) : agent( a ) {}
		void handle( Event* );
	private:
		AODViot	*agent;
		Event	intr;
};


/* Broadcast ID Cache */
class BroadcastID {

	friend class AODViot;

	public:
		BroadcastID( nsaddr_t i, u_int32_t b ) { src = i; id = b;	}
	protected:
		LIST_ENTRY( BroadcastID ) link;
		nsaddr_t	src;
		u_int32_t	 id;
		double		expire;	 // now + BCAST_ID_SAVE s
};

LIST_HEAD( aodvIot_bcache, BroadcastID );

/* The Routing Agent */
class AODViot: public Agent {

	/* make some friends first */

	friend class aodvIot_rt_entry;
	friend class IotBroadcastTimer;
	friend class IotHelloTimer;
	friend class IotNeighborTimer;
	friend class IotRouteCacheTimer;
	friend class IotLocalRepairTimer;
	friend class IotACKTimer;
	friend class IotRREQreBroadcastTimer;

	public:
		AODViot( nsaddr_t id );

	void	recv( Packet *p, Handler * );

	protected:
		int		 command( int, const char *const * );
		int		 initialized() { return 1 && target_; }

	/* Route Table Management */
		void		rt_resolve( Packet *p );
		void		rt_update( 	aodvIot_rt_entry *rt,
								u_int32_t seqnum,
								u_int16_t metric,
								nsaddr_t nexthop,
								double expire_time );
		void		rt_down( aodvIot_rt_entry *rt );
		void		local_rt_repair( aodvIot_rt_entry *rt, Packet *p );
	public:
		void		ShowRouteTable( nsaddr_t node );//ShowRouteTable
		void		rt_ll_failed( Packet *p );
		void		handle_link_failure( nsaddr_t id );
	protected:
		void		rt_purge( void );

		void		enque( aodvIot_rt_entry *rt, Packet *p );
		Packet*	 deque( aodvIot_rt_entry *rt );

	/* Neighbor Management */
		void		nb_insert( nsaddr_t id );
		AODViot_Neighbor*	 nb_lookup( nsaddr_t id );
		void		nb_delete( nsaddr_t id );
		void		nb_purge( void );

	/* Broadcast ID Management */
		void		id_insert( nsaddr_t id, u_int32_t bid );
		bool		id_lookup( nsaddr_t id, u_int32_t bid );
		void		id_purge( void );

	/* Packet TX Routines */
		void		forward( aodvIot_rt_entry *rt, Packet *p, double delay );
		void		sendHello( void );
		void		sendRequest( nsaddr_t dst );

		void		sendReply( 	nsaddr_t ipdst,
								u_int32_t hop_count,
								nsaddr_t rpdst,
								u_int32_t rpseq,
								u_int32_t lifetime,
								double timestamp );
		void		sendError( 	Packet *p,
								bool jitter = true );

		void		sendReply_ACK(  nsaddr_t Prev_Hop,
									nsaddr_t Org_IP );

	/* Packet RX Routines */
		void		recvAODViot( Packet *p );
		void		recvHello( Packet *p );
		void		recvRequest( Packet *p );
		void		recvReply( Packet *p );
		void		recvError( Packet *p );
		void		recvReply_ACK( Packet *p );

	/* History management */
		double		PerHopTime( aodvIot_rt_entry *rt );
		nsaddr_t	index;			// IP Address of this node
		u_int32_t	seqno;			// Sequence Number
		int		 	bid;			// Broadcast ID

		aodvIot_rtable	rthead;		 // routing table
		aodvIot_ncache	nbhead;		 // Neighbor Cache
		aodvIot_bcache	bihead;		 // Broadcast ID Cache

	/* Timers */
	IotBroadcastTimer		btimer;
	IotHelloTimer			htimer;
	IotNeighborTimer		ntimer;
	IotRouteCacheTimer		rtimer;
	IotLocalRepairTimer		lrtimer;
	IotACKTimer				acktimer;
	IotRREQreBroadcastTimer	reBtimer;

	/* Routing Table */
	aodvIot_rtable		rtable;

	/* A "drop-front" queue used by the routing layer to buffer
		packets to which it does not have a route.*/
	aodvIot_rqueue		rqueue;

	/* A mechanism for logging the contents of the routing table. */
	Trace		 *logtarget;

	/* A pointer to the network interface queue that sits between
		the "classifier" and the "link layer". */
	PriQueue	*ifqueue;

	/* Logging stuff */
	void		log_link_del( nsaddr_t dst );
	void		log_link_broke( Packet *p );
	void		log_link_kept( nsaddr_t dst );

	/* for passing packets up to agents */
	PortClassifier *dmux_;

};

#endif /* __aodvIot_h__ */

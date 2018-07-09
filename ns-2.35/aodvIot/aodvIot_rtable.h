/*DiLiver Unicorn 2018 CopyLeft NothingRights. */
/*Ver1.3 Master Graduate Vertion 2018/JUY/07 */

#ifndef __aodvIot_rtable_h__
#define __aodvIot_rtable_h__

#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>

#define CURRENT_TIME	Scheduler::instance().clock()
#define INFINITY2		0xff

/* AODViot Neighbor Cache Entry */
class AODViot_Neighbor {
	friend class AODViot;
	friend class aodvIot_rt_entry;
	
	public:
		AODViot_Neighbor(u_int32_t a){ nb_addr = a; }

	protected:
		LIST_ENTRY(AODViot_Neighbor) nb_link;
		nsaddr_t		nb_addr;
		double			nb_expire;		// ALLOWED_HELLO_LOSS * HELLO_INTERVAL
};

LIST_HEAD(aodvIot_ncache, AODViot_Neighbor);

/* AODViot Precursor list data structure */
class AODViot_Precursor {
	friend class AODViot;
	friend class aodvIot_rt_entry;
	
	public:
		AODViot_Precursor(u_int32_t a){ pc_addr = a; }
		
	protected:
		LIST_ENTRY(AODViot_Precursor) pc_link;
		nsaddr_t		pc_addr;	// precursor address
};

LIST_HEAD(aodvIot_precursors, AODViot_Precursor);


/* Route Table Entry */

class aodvIot_rt_entry {
	friend class aodvIot_rtable;
	friend class AODViot;
	friend class IotLocalRepairTimer;
	friend class IotACKTimer;
	friend class IotRREQreBroadcastTimer;
	
	public:
		aodvIot_rt_entry();
		~aodvIot_rt_entry();

		void				nb_insert(nsaddr_t id);
		AODViot_Neighbor*	nb_lookup(nsaddr_t id);
		
		void				pc_insert(nsaddr_t id);
		AODViot_Precursor*	pc_lookup(nsaddr_t id);
		void				pc_delete(nsaddr_t id);
		void				pc_delete(void);
		bool				pc_empty(void);

		double				rt_req_timeout;			// when I can send another req
		u_int8_t			rt_req_cnt;				// number of route requests
		u_int8_t			rt_rep_ack_cnt;			// number of RREP_ACK counts
		u_int8_t			rt_reqRebroadcast_cnt;	// number of reqRebroadcast counts


	protected:
		LIST_ENTRY(aodvIot_rt_entry) rt_link;

		nsaddr_t		rt_dst;
		u_int32_t		rt_seqno;
		u_int8_t		rt_interface;
		u_int16_t		rt_hops;			// hop count
		int				rt_last_hop_count;	// last valid hop count
		nsaddr_t		rt_nexthop;			// next hop IP address
		/* list of precursors */
		aodvIot_precursors rt_pclist;
		double			rt_expire;	 		// when entry expires
		int				rt_flags;

#define RTF_ACK_WAITING			 3
#define RTF_RREP_WAITING		 2
#define RTF_VAILD				 1
//THE RTF >0 means the route is available.
#define RTF_INVAILD				 0
#define RTF_BROADCASTING		-1	//I broadcast RREQ ,I'm waiting to hear the same packet ,so i can make sure the RREQ have successfully been forward.
#define RTF_DISCOVERING			-2	//I have heard the same RREQ which i broadcast,now im sure broadcast is successfull.
#define RTF_BROADCAST_FINISHED	-3	//RREQ has finish re-broadcast ,I'm waiting RREP.
#define RTF_IN_REPAIR			-4
// Note this is a good place to put the route state .add state if you need .

		/*
		 *	Must receive 4 errors within 3 seconds in order to mark
		 *	the route down.
		u_int8_t		rt_errors;		// error count
		double			rt_error_time;
#define MAX_RT_ERROR			4		 // errors
#define MAX_RT_ERROR_TIME		 3		 // seconds
		 */

#define MAX_HISTORY	3
	double		rt_disc_latency[MAX_HISTORY];
	char 		hist_indx;
		int 		rt_req_last_ttl;		// last ttl value used
	// last few route discovery latencies
	// double 		rt_length [MAX_HISTORY];
	// last few route lengths

		/*
		 * a list of neighbors that are using this route.
		 */
		aodvIot_ncache			rt_nblist;
};


/*
	The Routing Table
*/

class aodvIot_rtable {
 public:
	aodvIot_rtable(){ LIST_INIT(&rthead); }

		aodvIot_rt_entry*		 head(){ return rthead.lh_first; }

		aodvIot_rt_entry*		 rt_add(nsaddr_t id);
		void				 rt_delete(nsaddr_t id);
		aodvIot_rt_entry*		 rt_lookup(nsaddr_t id);

 private:
		LIST_HEAD(aodvIot_rthead, aodvIot_rt_entry) rthead;
};

#endif /* _aodvIot__rtable_h__ */

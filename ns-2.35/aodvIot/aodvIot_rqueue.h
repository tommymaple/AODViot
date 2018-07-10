/* AODViot v1.3.0.1 2018/JUY/10 */
/*DiLiver Unicorn 2018 CopyLeft NothingRights. */
/*Ver1.3 Master Graduate Vertion 2018/JUY/07 */

#ifndef __aodvIot_rqueue_h__
#define __aodvIot_rqueue_h_

//#include <packet.h>
#include <ip.h>
#include <agent.h>

/*
 * The maximum number of packets that we allow a routing protocol to buffer.
 */
#define AODViot_RTQ_MAX_LEN	 64		// packets

/*
 *	The maximum period of time that a routing protocol is allowed to buffer
 *	a packet for.
 */
#define AODViot_RTQ_TIMEOUT	 30	// seconds

class aodvIot_rqueue : public Connector {
 public:
		aodvIot_rqueue();

		void			recv( Packet *, Handler* ) { abort(); }

		void			enque( Packet *p );

	inline int		command( int argc, const char * const* argv )
		{ return Connector::command( argc, argv ); }

		/*
		 *	Returns a packet from the head of the queue.
		 */
		Packet*		 deque( void );

		/*
		 * Returns a packet for destination "D".
		 */
		Packet*		 deque( nsaddr_t dst );
	/*
	 * Finds whether a packet with destination dst exists in the queue
	 */
		char			find( nsaddr_t dst );

 private:
		Packet*		 remove_head();
		void			purge( void );
	void		findPacketWithDst( nsaddr_t dst, Packet*& p, Packet*& prev );
	bool 		findAgedPacket( Packet*& p, Packet*& prev );
	void		verifyQueue( void );

		Packet			*head_;
		Packet			*tail_;

		int			 len_;

		int			 limit_;
		double			timeout_;

};

#endif /* __aodvIot_rqueue_h__ */

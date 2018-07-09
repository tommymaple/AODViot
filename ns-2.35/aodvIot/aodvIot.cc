/*DiLiver Unicorn 2018 CopyLeft NothingRights. */
/*Ver1.3 Master Graduate Vertion 2018/JUY/07 */

#include <aodvIot/aodvIot.h>
#include <aodvIot/aodvIot_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <ip.h>
//#include <energy-model.h>

/* TCL Hooks */
int hdr_aodvIot::offset_;

static class AODViotHeaderClass : public PacketHeaderClass {
	public:
		AODViotHeaderClass() : PacketHeaderClass( "PacketHeader/AODViot",sizeof( hdr_all_aodvIot ) ) {
			bind_offset( &hdr_aodvIot::offset_ );
		}
} class_rtProtoAODViot_hdr;

static class AODViotclass : public TclClass {
	public:
		AODViotclass() : TclClass( "Agent/AODViot" ) {}
		TclObject* create( int argc, const char*const* argv ) {
			assert( argc == 5 );
			//return ( new AODViot( ( nsaddr_t ) atoi( argv[4] ) ) );
			return ( new AODViot( ( nsaddr_t ) Address::instance().str2addr( argv[4] ) ) );
		}
} class_rtProtoAODViot;

int AODViot::command( int argc, const char*const* argv ) {
	if( argc == 2 ) {
		Tcl& tcl = Tcl::instance();

		if( strncasecmp( argv[1], "id", 2 ) == 0 ) {
			tcl.resultf( "%d", index );
			return TCL_OK;
		}

		if( strncasecmp( argv[1], "start", 2 ) == 0 ) {
			btimer.handle( ( Event* ) 0 );

			#ifndef AODViot_LINK_LAYER_DETECTION
			  htimer.handle( ( Event* ) 0 );
			  ntimer.handle( ( Event* ) 0 );
			#endif // LINK LAYER DETECTION

			rtimer.handle( ( Event* ) 0 );
			return TCL_OK;
		}
	}
	else if( argc == 3 ) {
		if( strcmp( argv[1], "index" ) == 0 ) {
			index = atoi( argv[2] );
			return TCL_OK;
		}
		else if( strcmp( argv[1], "log-target" ) == 0 || strcmp( argv[1], "tracetarget" ) == 0 ) {
			logtarget = ( Trace* ) TclObject::lookup( argv[2] );

			if( logtarget == 0 )
				return TCL_ERROR;

			return TCL_OK;
		}
		else if( strcmp( argv[1], "drop-target" ) == 0 ) {
			int stat = rqueue.command( argc,argv );
			if( stat != TCL_OK )
				return stat;

			return Agent::command( argc, argv );
		}
		else if( strcmp( argv[1], "if-queue" ) == 0 ) {
			ifqueue = ( PriQueue* ) TclObject::lookup( argv[2] );

			if( ifqueue == 0 )
				return TCL_ERROR;

			return TCL_OK;
		}
		else if( strcmp( argv[1], "port-dmux" ) == 0 ) {
			dmux_ = ( PortClassifier * )TclObject::lookup( argv[2] );

			if( dmux_ == 0 ) {
				fprintf ( stderr, "%s: %s lookup of %s failed\n", __FILE__,argv[1], argv[2] );
				return TCL_ERROR;
			}

			return TCL_OK;
		}

	}
	return Agent::command( argc, argv );
}

/* Constructor */
AODViot::AODViot( nsaddr_t id ) : Agent( PT_AODViot ),
				btimer( this ), htimer( this ), ntimer( this ), rtimer( this ),
				lrtimer( this ), acktimer( this ), reBtimer( this ), rqueue() {
	index = id;
	seqno = 2;
	bid = 1;

	LIST_INIT( &nbhead );
	LIST_INIT( &bihead );

	logtarget = 0;
	ifqueue = 0;
}

/* Timers */

void IotBroadcastTimer::handle( Event* ) {
	agent->id_purge();
	Scheduler::instance().schedule( this, &intr, BCAST_ID_SAVE );
}
void IotHelloTimer::handle( Event* ) {
	RANDOM;
	agent->sendHello();
	double interval = MinHelloInterval +( ( MaxHelloInterval - MinHelloInterval ) * Random::uniform() );
	assert( interval >= 0 );
	Scheduler::instance().schedule( this, &intr, interval );
}
void IotNeighborTimer::handle( Event* ) {
	agent->nb_purge();
	Scheduler::instance().schedule( this, &intr, HELLO_INTERVAL );
}
void IotRouteCacheTimer::handle( Event* ) {
	agent->rt_purge();
	Scheduler::instance().schedule( this, &intr, FREQUENCY );
}
void IotLocalRepairTimer::handle( Event* p )	{// SRD: 5/4/99
	aodvIot_rt_entry *rt;
	struct hdr_ip *ih = HDR_IP( ( Packet * )p );

	/* you get here after the timeout in a local repair attempt */
		fprintf( stderr, "%s\n", __FUNCTION__ ); 

	rt = agent->rtable.rt_lookup( ih->daddr() );

	if( rt && rt->rt_flags != RTF_VAILD ) {
	// route is yet to be repaired 
	//I will be conservative and bring down the route and send route errors upstream.
	/* The following assert fails, not sure why */
	/* assert ( rt->rt_flags == RTF_IN_REPAIR ); */

	//rt->rt_seqno++;
	agent->rt_down( rt );
	// send RERR

	#ifdef DEBUG
	  fprintf( stderr,"Dst - %d, failed local repair\n", rt->rt_dst );
	#endif
	}
	Packet::free( ( Packet * )p );
}
void IotACKTimer::handle( Event* p ) {//2018 X Rosh

	struct hdr_ip *ih = HDR_IP( ( Packet * )p );

	aodvIot_rt_entry *rt0;
	rt0 = agent->rtable.rt_lookup( ih->daddr() );

	if( !rt0 )
	{
		printf( "!!!ERROR rt0 lookup fail! rt0:%p \n",rt0 );
		return;
	}

	if( rt0->rt_flags == RTF_ACK_WAITING )
	{
		if( ( CURRENT_TIME > rt0->rt_expire ) || ( rt0->rt_rep_ack_cnt >= RREP_ACK_RETRIES ) )//route time out
		{
			printf( "!!!time out/ over times\n" );///***
			printf( "CURRENT_TIME %f rt0->rt_expire %f rt0->rt_rep_ack_cnt %d RREP_ACK_RETRIES %d"
			,CURRENT_TIME,rt0->rt_expire,rt0->rt_rep_ack_cnt,RREP_ACK_RETRIES );
			
			rt0->rt_flags = RTF_INVAILD;
			
			//reset
			rt0->rt_rep_ack_cnt=0;
			
			return;
		}
		else
		{
			printf( "!!resend  RREP!\n" );///***
			rt0->rt_rep_ack_cnt++;

			Scheduler::instance().schedule( this,  ( ( Packet * )p )->copy(), RREP_ACK_WAIT_TIME );
			agent->forward( rt0, ( ( Packet * )p ), 0.0 );
		
		}
	}
}
void IotRREQreBroadcastTimer::handle( Event* p ) {//2018 X Rosh
	struct hdr_aodvIot_request *rq = HDR_AODViot_REQUEST( ( Packet * )p );
	aodvIot_rt_entry *rt;
	aodvIot_rt_entry *rt0;
	
	rt = agent->rtable.rt_lookup( rq->rq_Dst_IP );

	//來檢查路由 如果沒有代表沒有收到RREQ過( 收到RREQ就會建立 有效反向路由 與 失效的向前路由
	if( !rt )
	{
		printf( "<<<Critical ERROR>>> no forward route\n" );
		return;
	}
	
	rt0 = agent->rtable.rt_lookup( rq->rq_Org_IP );
		
	if( !rt0 && agent->index!=rq->rq_Org_IP )
	{
		printf( "<<<Critical ERROR>>> no Revers route\n" );
		return;
	}

	//before i rebroadcast check route table again.
	if ( rt->rt_flags > 0 )// if route is available now.
	{	
		
		//路由防呆
		
		//check IF this RREQ I'm the Originator
		if( rq->rq_Org_IP == agent->index )
			return;//My route has been discoverd so stop reBroadcast.
		
		if( rt->rt_nexthop == rt0->rt_nexthop )//同路進出( 我就是多餘的節點 )
			return;

		if( ( rt0->rt_flags <= 0 ) || ( rt0->rt_flags == RTF_RREP_WAITING ) )
		{
			agent->sendReply( 	rq->rq_Org_IP,
								rt->rt_hops + 1,
								rq->rq_Dst_IP,
								rt->rt_seqno,
								( u_int32_t ) ( rt->rt_expire - CURRENT_TIME ),	// rt->rt_expire - CURRENT_TIME,
								rq->rq_timestamp );
			return;
		}
	}

	if ( rt->rt_flags == RTF_BROADCASTING )
	{
		if( rt->rt_reqRebroadcast_cnt < RREQ_REBROADCAST_RETRIES ) // flag & rebroadcast times check
		{
			rt->rt_reqRebroadcast_cnt++;
			//RE-Send
			agent->forward( ( aodvIot_rt_entry* ) 0,  ( ( Packet * )p )->copy() , DELAY );
			//Timer
			Scheduler::instance().schedule( this, p ,RREQ_REBROADCAST_INTERVAL );

		}
		else
		{
			rt->rt_flags = RTF_BROADCAST_FINISHED;
			//counter reset.
			rt->rt_reqRebroadcast_cnt = 0;
		}
	}
}

/* Broadcast ID Management	Functions */

void AODViot::id_insert( nsaddr_t id, u_int32_t bid ) {
	BroadcastID *b = new BroadcastID( id, bid );

	assert( b );
	b->expire = CURRENT_TIME + BCAST_ID_SAVE;
	LIST_INSERT_HEAD( &bihead, b, link );
}
bool AODViot::id_lookup( nsaddr_t id, u_int32_t bid ) {// SRD
	BroadcastID *b = bihead.lh_first;

	// Search the list for a match of source and bid
	for( ; b; b = b->link.le_next ) {
		if( ( b->src == id ) && ( b->id == bid ) )
			return true;
	}

	return false;
}
void AODViot::id_purge() {
	BroadcastID *b = bihead.lh_first;
	BroadcastID *bn;
	double now = CURRENT_TIME;

	for( ; b; b = bn ) {
		bn = b->link.le_next;
		if( b->expire <= now ) {
			LIST_REMOVE( b,link );
			delete b;
		}
	}
}

/* Helper Functions */

double AODViot::PerHopTime( aodvIot_rt_entry *rt ) {
	int num_non_zero = 0, i;
	double total_latency = 0.0;

	if( !rt )
		return ( ( double ) NODE_TRAVERSAL_TIME );

	for ( i=0; i < MAX_HISTORY; i++ ) {
		if( rt->rt_disc_latency[i] > 0.0 ) {
			num_non_zero++;
			total_latency += rt->rt_disc_latency[i];
		}
	}

	if( num_non_zero > 0 )
		return( total_latency / ( double ) num_non_zero );
	else
		return( ( double ) NODE_TRAVERSAL_TIME );

}
// Link Failure Management Functions
static void aodvIot_rt_failed_callback( Packet *p, void *arg ) {
	( ( AODViot* ) arg )->rt_ll_failed( p );
}
// This routine is invoked when the link-layer reports a route failed.
void AODViot::rt_ll_failed( Packet *p ) {
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	aodvIot_rt_entry *rt;
	nsaddr_t broken_nbr = ch->next_hop_;

	#ifndef AODViot_LINK_LAYER_DETECTION
	  drop( p, DROP_RTR_MAC_CALLBACK );
	#else

	  /* Non-data packets and Broadcast Packets can be dropped. */

	  if( ! DATA_PACKET( ch->ptype() ) || ( u_int32_t ) ih->daddr() == IP_BROADCAST ) {
	  	drop( p, DROP_RTR_MAC_CALLBACK );
	  	return;
	  }

	  log_link_broke( p );

	  if( ( rt = rtable.rt_lookup( ih->daddr() ) ) == 0 ) {
		  drop( p, DROP_RTR_MAC_CALLBACK );
		  return;
	  }

	  log_link_del( ch->next_hop_ );

			#ifdef AODViot_LOCAL_REPAIR
			  /* if the broken link is closer to the dest than source,
			  attempt a local repair. Otherwise, bring down the route. */

			  if( ch->num_forwards() > rt->rt_hops ) {
			  	local_rt_repair( rt, p );
			  	/* local repair retrieve all the packets in the ifq using this link,
			  		queue the packets for which local repair is done,*/
			  	return;
			  }
			  else
			#endif // LOCAL REPAIR

	  {//?
	  drop( p, DROP_RTR_MAC_CALLBACK );
	  // Do the same thing for other packets in the interface queue using the
	  // broken link -Mahesh
		  while( ( p = ifqueue->filter( broken_nbr ) ) ) {
			  drop( p, DROP_RTR_MAC_CALLBACK );
		  }
		
		  nb_delete( broken_nbr );
	  }//?

	#endif // LINK LAYER DETECTION
}

void AODViot::handle_link_failure( nsaddr_t id ) {
	aodvIot_rt_entry *rt, *rtn;
	Packet *rerr = Packet::alloc();
	struct hdr_aodvIot_error *re = HDR_AODViot_ERROR( rerr );

	re->re_DestCount = 0;

	for( rt = rtable.head(); rt; rt = rtn ) {	// for each rt entry
		rtn = rt->rt_link.le_next;
		if( ( rt->rt_hops != INFINITY2 ) && ( rt->rt_nexthop == id ) ) {
			assert ( rt->rt_flags > 0 );
			assert( ( rt->rt_seqno%2 ) == 0 );
			rt->rt_seqno++;
			re->re_unreachable_dst[re->re_DestCount] = rt->rt_dst;
			re->re_unreachable_dst_seqno[re->re_DestCount] = rt->rt_seqno;

			#ifdef DEBUG
			  fprintf( stderr, "%s( %f ): %d\t( %d\t%u\t%d )\n",
					  __FUNCTION__,
					  CURRENT_TIME,
					  index,
					  re->re_unreachable_dst[re->re_DestCount],
					  re->re_unreachable_dst_seqno[re->re_DestCount],
					  rt->rt_nexthop );
			#endif // DEBUG

			re->re_DestCount += 1;
			rt_down( rt );
		}

		// remove the lost neighbor from all the precursor lists
		rt->pc_delete( id );
	}

	if( re->re_DestCount > 0 ) {
		#ifdef DEBUG
		  fprintf( stderr, "%s( %f ): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index );
		#endif // DEBUG

		sendError( rerr, false );
	}
	else {
	Packet::free( rerr );
	}
}

void AODViot::local_rt_repair( aodvIot_rt_entry *rt, Packet *p ) {
	#ifdef DEBUG
	  fprintf( stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst );
	#endif

	// Buffer the packet
	rqueue.enque( p );

	// mark the route as under repair
	rt->rt_flags = RTF_IN_REPAIR;

	sendRequest( rt->rt_dst );

	// set up a timer interrupt
	Scheduler::instance().schedule( &lrtimer, p->copy(), rt->rt_req_timeout );
}

void AODViot::rt_update( aodvIot_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
			 	nsaddr_t nexthop, double expire_time ) {

	rt->rt_seqno = seqnum;
	rt->rt_hops = metric;
	rt->rt_flags = RTF_VAILD;
	rt->rt_nexthop = nexthop;
	rt->rt_expire = expire_time;
}

void AODViot::rt_down( aodvIot_rt_entry *rt ) {
	/* Make sure that you don't "down" a route more than once. */
	if( rt->rt_flags == RTF_INVAILD )
		return;

	// assert ( rt->rt_seqno%2 ); // is the seqno odd?
	rt->rt_last_hop_count = rt->rt_hops;
	rt->rt_hops = INFINITY2;
	rt->rt_flags = RTF_INVAILD;
	rt->rt_nexthop = 0;
	rt->rt_expire = 0;

} /* rt_down function */

/* Route Handling Functions */

void AODViot::rt_resolve( Packet *p ) {
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	aodvIot_rt_entry *rt;

	/* Set the transmit failure callback. That won't change.*/
	ch->xmit_failure_ = aodvIot_rt_failed_callback;
	ch->xmit_failure_data_ = ( void* ) this;
	rt = rtable.rt_lookup( ih->daddr() );

	if( rt == 0 )
		rt = rtable.rt_add( ih->daddr() );

	/* If the route is up, forward the packet */
	if( rt->rt_flags > 0 ) {
		assert( rt->rt_hops != INFINITY2 );
		forward( rt, p, NO_DELAY );
	}
	/* if I am the source of the packet, then do a Route Request. */
	else if( ih->saddr() == index ) {
		rqueue.enque( p );
		sendRequest( rt->rt_dst );
	}
	/* A local repair is in progress. Buffer the packet. */
	else if( rt->rt_flags == RTF_IN_REPAIR ) {
		rqueue.enque( p );
	}

	/* I am trying to forward a packet for someone else to which I don't have a route. */

	else {
		Packet *rerr = Packet::alloc();
		struct hdr_aodvIot_error *re = HDR_AODViot_ERROR( rerr );
		/* For now, drop the packet and send error upstream.
			Now the route errors are broadcast to upstream neighbors - Mahesh 09/11/99 */

		assert ( rt->rt_flags == RTF_INVAILD );
		re->re_DestCount = 0;
		re->re_unreachable_dst[re->re_DestCount] = rt->rt_dst;
		re->re_unreachable_dst_seqno[re->re_DestCount] = rt->rt_seqno;
		re->re_DestCount += 1;

		#ifdef DEBUG
		 fprintf( stderr, "%s: sending RERR...\n", __FUNCTION__ );
		#endif

		sendError( rerr, false );

		drop( p, DROP_RTR_NO_ROUTE );
	}
}

void AODViot::rt_purge() {
	aodvIot_rt_entry *rt, *rtn;
	double now = CURRENT_TIME;
	double delay = 0.0;
	Packet *p;

	for( rt = rtable.head(); rt; rt = rtn ) {	// for each rt entry
		rtn = rt->rt_link.le_next;
		if( ( rt->rt_flags > 0 ) && ( rt->rt_expire < now ) ) {
			// if a valid route has expired, purge all packets from send buffer and invalidate the route.
			assert( rt->rt_hops != INFINITY2 );
			while( ( p = rqueue.deque( rt->rt_dst ) ) ) {
				#ifdef DEBUG
				 fprintf( stderr, "%s: calling drop()\n",__FUNCTION__ );
				#endif // DEBUG
			drop( p, DROP_RTR_NO_ROUTE );
			}

	 rt->rt_seqno++;
	 assert ( rt->rt_seqno%2 );
	 rt_down( rt );
	 }
	 else if( rt->rt_flags > 0 ) {
	 // If the route is not expired,
	 // and there are packets in the sendbuffer waiting,
	 // forward them. This should not be needed, but this extra
	 // check does no harm.
	 assert( rt->rt_hops != INFINITY2 );
	 while( ( p = rqueue.deque( rt->rt_dst ) ) ) {
		 forward ( rt, p, delay );
		 delay += ARP_DELAY;
	 }
	 }
	 else if( rqueue.find( rt->rt_dst ) )
	 // If the route is down and
	 // if there is a packet for this destination waiting in
	 // the sendbuffer, then send out route request. sendRequest
	 // will check whether it is time to really send out request
	 // or not.
	 // This may not be crucial to do it here, as each generated
	 // packet will do a sendRequest anyway.

	 sendRequest( rt->rt_dst );
	 }

}

/* Packet Reception Routines */

void AODViot::recv( Packet *p, Handler* ) {
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );

	assert( initialized() );
	//assert( p->incoming == 0 );
	/* XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow,
					direction_ in hdr_cmn is used instead. see packet.h for details.*/

	if( ch->ptype() == PT_AODViot ) {
		ih->ttl_ -= 1;
		recvAODViot( p );
		return;
	}

	/* Must be a packet I'm originating... */
	if( ( ih->saddr() == index ) && ( ch->num_forwards() == 0 ) ) {
		/* Add the IP Header. * TCP adds the IP header too, so to avoid setting it twice, we check if
			this packet is not a TCP or ACK segment. */
		if( ch->ptype() != PT_TCP && ch->ptype() != PT_ACK ) {
			ch->size() += IP_HDR_LEN;
		}

		// Added by Parag Dadhania && John Novatnack to handle broadcasting
		if( ( u_int32_t )ih->daddr() != IP_BROADCAST ) {
			ih->ttl_ = NETWORK_DIAMETER;
		}
	}

	/* I received a packet that I sent.	Probably a routing loop. */
	else if( ih->saddr() == index ) {
		drop( p, DROP_RTR_ROUTE_LOOP );
		return;
	}
	/* Packet I'm forwarding... */
	else {
		/* Check the TTL.	If it is zero, then discard. */
		if( --ih->ttl_ == 0 ) {
			drop( p, DROP_RTR_TTL );
			return;
		}
	}

	// Added by Parag Dadhania && John Novatnack to handle broadcasting
	if( ( u_int32_t )ih->daddr() != IP_BROADCAST )
		rt_resolve( p );
	else
		forward( ( aodvIot_rt_entry* ) 0, p, NO_DELAY );
}

void AODViot::recvAODViot( Packet *p ) {
	struct hdr_aodvIot *ah = HDR_AODViot( p );

	assert( HDR_IP ( p )->sport() == RT_POrt );
	assert( HDR_IP ( p )->dport() == RT_POrt );

	/* * Incoming Packets. */
	switch( ah->ah_type ) {

		case AODViotTYPE_RREQ:
			recvRequest( p );
			break;

		case AODViotTYPE_RREP:
			recvReply( p );
			break;

		case AODViotTYPE_RERR:
			recvError( p );
			break;

		case AODViotTYPE_HELLO:
			recvHello( p );
			break;
			
		case AODViotTYPE_RREP_ACK:
			recvReply_ACK( p );
			break;

		default:
			fprintf( stderr, "Invalid AODViot type ( %x )\n", ah->ah_type );
			exit( 1 );
	}
}

void AODViot::recvRequest( Packet *p ) {

	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_request *rq = HDR_AODViot_REQUEST( p );

	bool RouteTableUpdate=false;

	aodvIot_rt_entry *rt;
	aodvIot_rt_entry *rt0; // rt0 is the reverse route

#ifdef ShowAODViot_Packet_RREQ_Recv
  printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
  printf( BLU"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
  printf( "|R AODViot RREQ |%d|%d|%d|%d|%d|      Reserved       |  %10d   |\n",
          rq->rq_RREQ_J,rq->rq_RREQ_R,rq->rq_RREQ_G,rq->rq_RREQ_D,rq->rq_RREQ_U,rq->rq_hop_count );
  printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
  #ifdef Show_Packet_detail
    printf( "|    Destination  IP      : %16d                    |\n",rq->rq_Dst_IP );
    printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
    printf( "|    Destination  SeqNo   : %16d                    |\n",rq->rq_Dst_seqno );
    printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
    printf( "|    Originator   IP      : %16d                    |\n",rq->rq_Org_IP );
    printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
    printf( "|    Originator   SeqNo   : %16d                    |\n",rq->rq_Org_seqno );
    printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
    #ifdef RREQ_ID
      printf( "|       RREQ      ID      : %16d                    |\n",rq->rq_RREQ_ID );
      printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
    #endif //end of ifdef RREQ_ID
  #endif //end of ifdef Show_Packet_detail
#endif

	/** Initial phase **/

#ifdef RREQ_ID //I scrapped this function. If you want to use this, turn it on at aodvIot.h
  /* Drop if: I recently heard this request. */
  if( id_lookup( rq->rq_Org_IP, rq->rq_RREQ_ID ) ) {
     #ifdef DEBUG
        fprintf( stderr, "%s: I recently heard this request. discarding...\n", __FUNCTION__ );
      #endif // DEBUG

  /** End phase **/
    Packet::free( p );
    return;
  }

	  /* Cache the RREQ ID ( broadcast ID )*/
	  id_insert( rq->rq_Org_IP, rq->rq_RREQ_ID );//orginator need cache its own ID too ,at RREQ send before.( RFC )
	#endif


	///I'm the Originator
	if( rq->rq_Org_IP == index ) {
		#ifdef DEBUG
		  fprintf( stderr, "%s:I'm the Originator got my own REQUEST\n", __FUNCTION__ );
		#endif // DEBUG

	/** Routing Table Phase **/
		rt = rtable.rt_lookup( rq->rq_Dst_IP );

		if( rt->rt_flags == RTF_BROADCASTING ) { //update Forward Routing table entry >> route state
			rt->rt_flags = RTF_DISCOVERING ;
			rt->rt_reqRebroadcast_cnt = 0;
		}

	/** End phase **/
		Packet::free( p );
		return;
	}
	///I'm the destination
	else if( rq->rq_Dst_IP == index ) {
		#ifdef DEBUG
		  fprintf( stderr, "%s:I'm the destination\n", __FUNCTION__ );
		#endif // DEBUG

	/** Routing Table Phase **/
		rt0 = rtable.rt_lookup( rq->rq_Org_IP );

		if( !rt0 ) /* if reverse route not in the route table create an entry for the reverse route.*/
			rt0 = rtable.rt_add( rq->rq_Org_IP );

		rt0->rt_expire = max( rt0->rt_expire, ( CURRENT_TIME + REV_ROUTE_LIFE ) );

		if( ( rq->rq_Org_seqno > rt0->rt_seqno ) ||
			( ( rq->rq_Org_seqno == rt0->rt_seqno ) && ( rq->rq_hop_count < rt0->rt_hops ) ) ||
			( rq->rq_RREQ_U ) ) {
			// If we have a fresher seq no. or
			// lesser #hops for the same seq no. or
			// unknown Flag is up 
			// ,update the rt entry. Else don't bother.

			rt_update( rt0,
						rq->rq_Org_seqno,
						rq->rq_hop_count,
						ih->saddr(),
						max( rt0->rt_expire, ( CURRENT_TIME + REV_ROUTE_LIFE ) ) );
			
			rt0->rt_flags=RTF_RREP_WAITING;
			//TODO RTF_RREP_WAITING TIMEOUT COUNTER

			if( rt0->rt_req_timeout > 0.0 ) {
				/* Reset the soft state and Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
					This is because route is used in the forward direction, but only sources get benefited by this change*/
				rt0->rt_req_cnt = 0;
				rt0->rt_req_timeout = 0.0;
							
				rt0->rt_req_last_ttl = rq->rq_hop_count;
				rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
			}
			
			RouteTableUpdate=true;
		}// End for putting reverse route in rt table

	/** Flag process & Send phase **/
		// Just to be safe, I use the max. Somebody may have incremented the dst seqno.
		seqno = max( seqno, rq->rq_Dst_seqno )+1;
		if( seqno%2 ) seqno++;
			sendReply( rq->rq_Org_IP,			 // IP Destination
					1,					// Hop Count
					index,				// Dest IP Address
					seqno,				// Dest Sequence Num
					MY_ROUTE_TIMEOUT,	// Lifetime
					rq->rq_timestamp );	// timestamp

	/** End phase **/
	
		Packet::free( p );
		

	}
	///I'm the intermidate node
	else{
		#ifdef DEBUG
		  fprintf( stderr, "%s:I'm intermidate node\n", __FUNCTION__ );
		#endif // DEBUG
	/** Routing Table Phase **/
		rt = rtable.rt_lookup( rq->rq_Dst_IP );

		if( !rt ) {//If Forward route not in the route table
			rt = rtable.rt_add( rq->rq_Dst_IP );
			rt->rt_flags = RTF_BROADCASTING;
		}
		else{ //update Forward Routing table entry >> route state
			if( rt->rt_flags == RTF_BROADCASTING ) { //update Forward Routing table entry >> route state
				rt->rt_flags = RTF_DISCOVERING ;
				rt->rt_reqRebroadcast_cnt = 0;
			}
		}

		rt0 = rtable.rt_lookup( rq->rq_Org_IP );

		/* if not in the route table */
		if( !rt0 ) // create an entry for the reverse route.
			rt0 = rtable.rt_add( rq->rq_Org_IP );


		rt0->rt_expire = max( rt0->rt_expire, ( CURRENT_TIME + REV_ROUTE_LIFE ) );

		if( ( rq->rq_Org_seqno > rt0->rt_seqno ) ||
			( ( rq->rq_Org_seqno == rt0->rt_seqno ) && ( rq->rq_hop_count < rt0->rt_hops ) ) ||
			( rq->rq_RREQ_U ) ) {

			rt_update( rt0,
						rq->rq_Org_seqno,
						rq->rq_hop_count,
						ih->saddr(),
						max( rt0->rt_expire, ( CURRENT_TIME + REV_ROUTE_LIFE ) ) );
						
			rt0->rt_flags=RTF_RREP_WAITING;
			
			if( rt0->rt_req_timeout > 0.0 ) {
				rt0->rt_req_cnt = 0;
				rt0->rt_req_timeout = 0.0;
				rt0->rt_req_last_ttl = rq->rq_hop_count;
				rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
				
				rt->rt_reqRebroadcast_cnt = 0;
			}
			
			RouteTableUpdate = true;

		}// End for putting reverse route in rt table

	/** Flag process & Send phase **/
		if( ( rt->rt_flags > 0 ) &&
			( rt->rt_seqno >= rq->rq_Dst_seqno ) &&
			( !rq->rq_RREQ_D ) ) {
			
			assert( rq->rq_Dst_IP == rt->rt_dst );
			
			if( rq->rq_hop_count <= rt0->rt_hops ) { //繞路防治
				sendReply( rq->rq_Org_IP,
						rt->rt_hops + 1,
						rq->rq_Dst_IP,
						rt->rt_seqno,
						( u_int32_t ) ( rt->rt_expire - CURRENT_TIME ),
						//			 rt->rt_expire - CURRENT_TIME,
						rq->rq_timestamp );

				// Insert nexthops to RREQ source and RREQ destination in the
				// precursor lists of destination and source respectively
				rt->pc_insert( rt0->rt_nexthop ); // nexthop to RREQ source
				rt0->pc_insert( rt->rt_nexthop ); // nexthop to RREQ destination

				// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_Org_seqno, rq->rq_hop_counT
				/* DONE: Included gratuitous replies to be sent as per IETF aodvIot draft specification. As of now,
				G flag has not been dynamically used and is always set or reset in aodvIot-packet.h --- Anant Utgikar, 09/16/02.*/
				if( rq->rq_RREQ_G )
					sendReply( 	rq->rq_Dst_IP,
								rq->rq_hop_count,
								rq->rq_Org_IP,
								rq->rq_Org_seqno,
								( u_int32_t ) ( rt->rt_expire - CURRENT_TIME ),
								rq->rq_timestamp );
			}

			Packet::free( p );

		}
		/* Can't reply. So forward the	Route Request */
		else {
			ih->saddr() = index;
			ih->daddr() = IP_BROADCAST;
			rq->rq_hop_count += 1;
			// Maximum sequence number seen en route
			if( rt )
				rq->rq_Dst_seqno = max( rt->rt_seqno, rq->rq_Dst_seqno );

			if( RouteTableUpdate ) {
				#ifdef RREQ_Rebroadcast
				  rt->rt_reqRebroadcast_cnt = 0;
				  rt->rt_flags = RTF_BROADCASTING;
				  Scheduler::instance().schedule( &reBtimer,p->copy(),RREQ_REBROADCAST_INTERVAL );
				#endif
				
				forward( ( aodvIot_rt_entry* ) 0, p, DELAY );
				
			}
		}
		
	/** End phase **/
		
	}//END OF I'm the intermidate node
	
	
	/* Send all packets queued in the sendbuffer destined for this destination. 
		Puts this shit after sending control packet, control packet needs priority. 2018 X Rosh
		XXX - observe the "second" use of p. */
	if( RouteTableUpdate ) {
		assert ( rt0->rt_flags > 0 );

		Packet *buffered_pkt;
		while ( ( buffered_pkt = rqueue.deque( rt0->rt_dst ) ) ) {
			if( rt0 && ( rt0->rt_flags > 0 ) ) {
				assert( rt0->rt_hops != INFINITY2 );
				forward( rt0, buffered_pkt, NO_DELAY );
			}
		}
	}
	
	return;
}

void AODViot::recvReply( Packet *p ) {
	//struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_reply *rp = HDR_AODViot_REPLY( p );
	aodvIot_rt_entry *rt;
	aodvIot_rt_entry *rt0;
	bool RouteTableUpdate=false;
	double delay = 0.0;
	

#ifdef ShowAODViot_Packet_RREP_Recv
printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf(GRN"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
printf( "|R AODViot RREP |%d|%d|    Reserved     |Prefix Sz|  %10d   |\n",rp->rp_RREP_R,rp->rp_RREP_A,rp->rp_hop_count );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST);
 #ifdef Show_Packet_detail
printf( "|    Destination  IP      : %16d                    |\n",rp->rp_Dst_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Destination  SeqNo   : %16d                    |\n",rp->rp_Dst_Seqno );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Previous Hop IP      : %16d                    |\n",rp->rp_Prev_Hop_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|        Life Time        :        %16.6f             |\n",rp->rp_lifetime );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 #endif
#endif

#ifdef DEBUG
  fprintf( stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__ );
#endif // DEBUG

	rt = rtable.rt_lookup( rp->rp_Dst_IP );

	/* Got a reply. So reset the "soft state" maintained for route requests in the request table.
		We don't really have have a separate request table. It is just a part of the routing table itself. */
	
	//Im Originator
	if( ih->daddr() == index ) {
		
		
		/* If I don't have a rt entry to this host... adding */
		if( !rt )
			rt = rtable.rt_add( rp->rp_Dst_IP );
		
		if( ( rt->rt_seqno < rp->rp_Dst_Seqno ) ||	// newer route
			( ( rt->rt_seqno == rp->rp_Dst_Seqno ) && ( rt->rt_hops > rp->rp_hop_count ) ) ) { // shorter or better route

			// Update the rt entry
			rt_update( 	rt,
						rp->rp_Dst_Seqno,
						rp->rp_hop_count,
						rp->rp_Prev_Hop_IP,
						CURRENT_TIME + rp->rp_lifetime );

			// reset the soft state
			rt->rt_req_cnt = 0;
			rt->rt_req_timeout = 0.0;
			rt->rt_reqRebroadcast_cnt = 0;
			rt->rt_req_last_ttl = rp->rp_hop_count;
		
			RouteTableUpdate=true;
		}
		
		if( rp->rp_RREP_A ) {
			//originator No need to RTF_ACK_WAITING;
			sendReply_ACK( rp->rp_Prev_Hop_IP ,ih->daddr() );
		}
		
		// Update the route discovery latency statistics rp->rp_timestamp is the time of request origination
		rt->rt_disc_latency[( unsigned char )rt->hist_indx] = ( CURRENT_TIME - rp->rp_timestamp ) / ( double ) rp->rp_hop_count;
		// increment indx for next time
		rt->hist_indx = ( rt->hist_indx + 1 ) % MAX_HISTORY;
		
		Packet::free( p );
	}
	//Im intermidate node 
	else{
	
		rt0 = rtable.rt_lookup( ih->daddr() );

		/* If I don't have a rt entry to this host... adding */
		if( !rt ) {
			rt = rtable.rt_add( rp->rp_Dst_IP );
		}
			
		if( ( rt->rt_seqno < rp->rp_Dst_Seqno ) ||	// newer route
			( ( rt->rt_seqno == rp->rp_Dst_Seqno ) && ( rt->rt_hops > rp->rp_hop_count ) ) ) { // shorter or better route

			// Update the rt entry
			rt_update( 	rt,
						rp->rp_Dst_Seqno,
						rp->rp_hop_count,
						rp->rp_Prev_Hop_IP,
						CURRENT_TIME + rp->rp_lifetime );

			// reset the soft state
			rt->rt_req_cnt = 0;
			rt->rt_req_timeout = 0.0;
			rt->rt_reqRebroadcast_cnt = 0;
			rt->rt_req_last_ttl = rp->rp_hop_count;
			
			RouteTableUpdate=true;
		}
		
		if( rp->rp_RREP_A ) {
			rt0->rt_flags = RTF_ACK_WAITING;
			sendReply_ACK( rp->rp_Prev_Hop_IP ,ih->daddr() );
			Scheduler::instance().schedule( &acktimer, p->copy(), RREP_ACK_WAIT_TIME );// timer
		}
		
		// If the rt is up, forward. flag value bigger then 0 means route is available.
		if( rt0->rt_flags > 0 ) {
			if( RouteTableUpdate || ( rt0->rt_flags == RTF_RREP_WAITING ) ) {
				//這邊+RTF_RREP_WAITING這個條件可以讓ACK bypass forward 規則
				
				assert ( rt0->rt_flags > 0 );
				rp->rp_hop_count += 1;
				rp->rp_Prev_Hop_IP = index;
				
				forward( rt0, p, NO_DELAY );
				
				if( rt0->rt_flags != RTF_ACK_WAITING )//RTF_ACK_WAITING have higher priority 
					rt0->rt_flags = RTF_VAILD;//Forward 完 RREP_WAITING 要恢復成 VAILD しかし！A Flag 狀態優先
				
				// Insert the nexthop towards the RREQ source to the precursor list of the RREQ destination
				rt->pc_insert( rt0->rt_nexthop ); // nexthop to RREQ source
			}
		}
		else {//TODO :this may need to fix
			// I don't know how to forward .. drop the reply.
			#ifdef DEBUG
			  fprintf( stderr, "%s: dropping Route Reply\n", __FUNCTION__ );
			#endif // DEBUG
			drop( p, DROP_RTR_NO_ROUTE );
		}
	}//END OF Im intermidate node
	
	
	/* Send all packets queued in the sendbuffer destined for this destination.
	Puts this shit after sending AODViot control packet, control packet needs priority! 2018APR X Rosh
	XXX - observe the "second" use of p. */
	if( RouteTableUpdate ) {
		Packet *buf_pkt;
		while( ( buf_pkt = rqueue.deque( rt->rt_dst ) ) ) {
			if( rt->rt_hops != INFINITY2 ) {
				assert ( rt->rt_flags > 0 );
				// Delay them a little to help ARP. Otherwise ARP
				// may drop packets. -SRD 5/23/99
				//i dont know why , can somebody proof this? 2018Rosh
				forward( rt, buf_pkt, delay );
				delay += ARP_DELAY;
			}
		}
	}
	return;
}

void AODViot::recvError( Packet *p ) {
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_error *re = HDR_AODViot_ERROR( p );
	aodvIot_rt_entry *rt;
	u_int8_t i;
	Packet *rerr = Packet::alloc();
	struct hdr_aodvIot_error *nre = HDR_AODViot_ERROR( rerr );

	nre->re_DestCount = 0;

 #ifdef ShowAODViot_Packet_RERR_Recv
printf( "\nTIME:%.9f Node:%d    IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf( RED"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|R AODViot RERR |%d|          Reserved           |  %10d   |\n",re->re_RERR_N,re->re_DestCount );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
 #ifdef Show_Packet_detail
 for( int i = 0 ; i<re->re_DestCount ; i++ )
 {
	printf( "|Unreachable Destination  IP  :%32d |\n",re->re_unreachable_dst[i] );
	printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
	printf( "|Unreachable Destination SeqNo:%32d |\n",re->re_unreachable_dst_seqno[i] );
	printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 }
 #endif
#endif

	for ( i=0; i<re->re_DestCount; i++ ) {
		// For each unreachable destination
		rt = rtable.rt_lookup( re->re_unreachable_dst[i] );
		if( rt && ( rt->rt_hops != INFINITY2 ) &&
				( rt->rt_nexthop == ih->saddr() ) &&
				( rt->rt_seqno <= re->re_unreachable_dst_seqno[i] ) ) {

			assert( rt->rt_flags > 0 );
			assert( ( rt->rt_seqno%2 ) == 0 ); // is the seqno even?
			#ifdef DEBUG
			fprintf( stderr, "%s( %f ): %d\t( %d\t%u\t%d )\t( %d\t%u\t%d )\n", __FUNCTION__,CURRENT_TIME,
					index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
					re->re_unreachable_dst[i],re->re_unreachable_dst_seqno[i],
					ih->saddr() );
			#endif // DEBUG

			rt->rt_seqno = re->re_unreachable_dst_seqno[i];
			rt_down( rt );

			// Not sure whether this is the right thing to do
			Packet *pkt;
			while( ( pkt = ifqueue->filter( ih->saddr() ) ) ) {
				drop( pkt, DROP_RTR_MAC_CALLBACK );
			}

			// if precursor list non-empty add to RERR and delete the precursor list
			if( !rt->pc_empty() ) {
				nre->re_unreachable_dst[nre->re_DestCount] = rt->rt_dst;
				nre->re_unreachable_dst_seqno[nre->re_DestCount] = rt->rt_seqno;
				nre->re_DestCount += 1;
				rt->pc_delete();
			}
		}
	}

	if( nre->re_DestCount > 0 ) {
		#ifdef DEBUG
		  fprintf( stderr, "%s( %f ): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index );
		#endif // DEBUG
		sendError( rerr );
	}
	else {
		Packet::free( rerr );
	}

	Packet::free( p );
}

void AODViot::recvReply_ACK( Packet *p ) {
	struct hdr_aodvIot_rrep_ack *ra = HDR_AODViot_RREP_ACK( p );

	aodvIot_rt_entry *rt0;

#ifdef DEBUG
fprintf( stderr, "%d - %s: received a REPLY_ACK\n", index, __FUNCTION__ );
#endif // DEBUG

#ifdef ShowAODViot_Packet_RREP_ACK_Recv
struct hdr_ip *ih = HDR_IP( p );//using at above to show packet. Ignore the warning.
printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf( YEL"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|R AODViot RREP ACK|                  Reserved                  |\n" );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
 #ifdef Show_Packet_detail
printf( "+    Originator    IP    :    %8d                          |\n",ra->rpack_Org_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 #endif
#endif

	/* Initial Phase( RecvRREP_ACK ) */
	rt0=rtable.rt_lookup( ra->rpack_Org_IP );

	if( !rt0 )
		printf( "This SHOULD NOT BE HAPPENED! rt0 not exist\n" );


	/* routing table phase */
	if( rt0->rt_flags == RTF_ACK_WAITING )
		rt0->rt_flags = RTF_VAILD; //route state 1 : valid
	else{
		printf("ERROR !!! received a REPLY_ACK but im not in waiting.\n");
		#ifdef DEBUG
		fprintf( stderr, "%d - %s: received a REPLY_ACK but im not in waiting.\n", index, __FUNCTION__ );
		#endif // DEBUG
	}

	/* End Phase( RecvRREP_ACK ) */

	Packet::free( p );
	return;
}


/* Packet Transmission Routines */

void AODViot::forward( aodvIot_rt_entry *rt, Packet *p, double delay ) {
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih ;
	ih = HDR_IP( p );
	RANDOM;
	if( ih->ttl_ == 0 ) {
		#ifdef DEBUG
		  fprintf( stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__ );
		#endif // DEBUG

		drop( p, DROP_RTR_TTL );
		return;
	}

	if( ( ( ch->ptype() != PT_AODViot && ch->direction() == hdr_cmn::UP ) &&
			( ( u_int32_t )ih->daddr() == IP_BROADCAST ) )
			|| ( ih->daddr() == here_.addr_ ) ) {
		dmux_->recv( p,0 );
		return;
	}

	if( rt ) {
		assert( rt->rt_flags > 0 );
		rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
		ch->next_hop_ = rt->rt_nexthop;
		ch->addr_type() = NS_AF_INET;
		ch->direction() = hdr_cmn::DOWN;		 //important: change the packet's direction
	}
	else { // if it is a broadcast packet
		// assert( ch->ptype() == PT_AODViot ); // maybe a diff pkt type like gaf
		assert( ih->daddr() == ( nsaddr_t ) IP_BROADCAST );
		ch->addr_type() = NS_AF_NONE;
		ch->direction() = hdr_cmn::DOWN;		 //important: change the packet's direction
	}

	if( ih->daddr() == ( nsaddr_t ) IP_BROADCAST ) {
		// If it is a broadcast packet
		assert( rt == 0 );
		if( ch->ptype() == PT_AODViot ) {
			/* Jitter the sending of AODViot broadcast packets by 10ms */
			Scheduler::instance().schedule( target_, p, 0.01 * Random::uniform() );
		}
		else {
			Scheduler::instance().schedule( target_, p, 0. );	// No jitter
		}

	}
	else { // Not a broadcast packet



		if( delay > 0.0 ) {
			Scheduler::instance().schedule( target_, p, delay );
		}
		else {
			// Not a broadcast packet, no delay, send immediately
			Scheduler::instance().schedule( target_, p, 0. );
		}
	}
}

void AODViot::sendRequest( nsaddr_t dst ) {
	// Allocate a RREQ packet
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_request *rq = HDR_AODViot_REQUEST( p );
	aodvIot_rt_entry *rt = rtable.rt_lookup( dst );

	assert( rt );

	/* Rate limit sending of Route Requests.
		We are very conservative about sending out route requests. */

	if( rt->rt_flags > 0 ) {
		assert( rt->rt_hops != INFINITY2 );
		Packet::free( ( Packet * )p );
		return;
	}

	if( rt->rt_req_timeout > CURRENT_TIME ) {
		Packet::free( ( Packet * )p );
		return;
	}

	// rt_req_cnt is the no. of times we did network-wide broadcast
	// RREQ_RETRIES is the maximum number we will allow before
	// going to a long timeout.


	if( rt->rt_req_cnt > RREQ_RETRIES ) {
		rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
		rt->rt_req_cnt = 0;
		Packet *buf_pkt;

		while ( ( buf_pkt = rqueue.deque( rt->rt_dst ) ) ) {
			drop( buf_pkt, DROP_RTR_NO_ROUTE );
		}

		Packet::free( ( Packet * )p );
		return;
	}

	#ifdef DEBUG
	  fprintf( stderr, "( %2d ) - %2d sending Route Request, dst: %d\n",++route_request, index, rt->rt_dst );
	#endif // DEBUG

	// Determine the TTL to be used this time. Dynamic TTL evaluation - SRD

	rt->rt_req_last_ttl = max( rt->rt_req_last_ttl,rt->rt_last_hop_count );

	if( 0 == rt->rt_req_last_ttl ) {
		// first time query broadcast
		ih->ttl_ = TTL_START;
	}
	else {
		// Expanding ring search.
		if( rt->rt_req_last_ttl < TTL_THRESHOLD )
			ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
		else {
			// network-wide broadcast
			ih->ttl_ = NETWORK_DIAMETER;
			rt->rt_req_cnt += 1;
		}
	}

	// remember the TTL used	for the next time
	rt->rt_req_last_ttl = ih->ttl_;

	// PerHopTime is the roundtrip time per hop for route requests.
	// The factor 2.0 is just to be safe .. SRD 5/22/99
	// Also note that we are making timeouts to be larger if we have
	// done network wide broadcast before.
	rt->rt_req_timeout = 2.0 * ( double ) ih->ttl_ * PerHopTime( rt );

	if( rt->rt_req_cnt > 0 )
		rt->rt_req_timeout *= rt->rt_req_cnt;

	rt->rt_req_timeout += CURRENT_TIME;

	// Don't let the timeout to be too large, however .. SRD 6/8/99
	if( rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT )
		rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;

	rt->rt_expire = 0;

	#ifdef DEBUG
	  fprintf( stderr, "( %2d ) - %2d sending Route Request, dst: %d, tout %f ms\n",
			  ++route_request,
			  index, rt->rt_dst,
			  rt->rt_req_timeout - CURRENT_TIME );
	#endif	// DEBUG

	// Fill out the RREQ packet
	// ch->uid() = 0;
	ch->ptype() = PT_AODViot;
	ch->size() = IP_HDR_LEN + rq->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->prev_hop_ = index;			// AODViot hack

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;

	// Fill up some more fields.
	rq->rq_type = AODViotTYPE_RREQ;
	rq->rq_hop_count = 1;

	#ifdef RREQ_ID
	  rq->rq_RREQ_ID = bid++;
	#else
	  rq->rq_RREQ_ID = 0; //
	#endif
	
	#ifdef RREQ_G
	rq->rq_RREQ_G=1;
	#endif
	
	#ifdef RREQ_D
	rq->rq_RREQ_D=1;
	#endif
	
	#ifdef RREQ_U
	if( rt->rt_seqno <= 0 )
		rq->rq_RREQ_U=1;
	
	//this flag can force update route any time when its on.
	// some times if u need update route use this flag! and code your self. 2018APR X Rosh 
	#endif
	
	
	rq->rq_Dst_IP = dst;
	rq->rq_Dst_seqno = ( rt ? rt->rt_seqno : 0 );
	rq->rq_Org_IP = index;
	seqno += 2;
	assert ( ( seqno%2 ) == 0 );
	rq->rq_Org_seqno = seqno;
	rq->rq_timestamp = CURRENT_TIME;

	Scheduler::instance().schedule( target_, p, 0. );
	
 #ifdef RREQ_Rebroadcast
 rt->rt_reqRebroadcast_cnt = 0;
 rt->rt_flags = -1;
 Scheduler::instance().schedule( &reBtimer,p->copy(),RREQ_REBROADCAST_INTERVAL );
 #endif

#ifdef ShowAODViot_Packet_RREQ_Send
printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf( BLU"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|S AODViot RREQ |%d|%d|%d|%d|%d|      Reserved       |  %10d   |\n",
		rq->rq_RREQ_J,rq->rq_RREQ_R,rq->rq_RREQ_G,rq->rq_RREQ_D,rq->rq_RREQ_U,rq->rq_hop_count );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
 #ifdef Show_Packet_detail
    #ifdef RREQ_ID
      printf( "|       RREQ      ID      : %16d                    |\n",rq->rq_RREQ_ID );
      printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
	#endif //end of ifdef RREQ_ID
printf( "|    Destination  IP      : %16d                    |\n",rq->rq_Dst_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Destination  SeqNo   : %16d                    |\n",rq->rq_Dst_seqno );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Originator   IP      : %16d                    |\n",rq->rq_Org_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Originator   SeqNo   : %16d                    |\n",rq->rq_Org_seqno );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 #endif
#endif
}

void AODViot::sendReply( nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
						u_int32_t rpseq, u_int32_t lifetime, double timestamp ) {
	
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_reply *rp = HDR_AODViot_REPLY( p );
	
	aodvIot_rt_entry *rt0 = rtable.rt_lookup( ipdst );

	#ifdef DEBUG
	  fprintf( stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock() );
	#endif // DEBUG

	assert( rt0 );

	rp->rp_type = AODViotTYPE_RREP;
	rp->rp_hop_count = hop_count;
	rp->rp_Dst_IP = rpdst;///!!
	rp->rp_Dst_Seqno = rpseq;
	rp->rp_Prev_Hop_IP = index;
	rp->rp_lifetime = lifetime;
	rp->rp_timestamp = timestamp;

	ch->ptype() = PT_AODViot;
	ch->size() = IP_HDR_LEN + rp->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_INET;
	ch->next_hop_ = rt0->rt_nexthop;
	ch->prev_hop_ = index;			// AODViot hack
	ch->direction() = hdr_cmn::DOWN;

	ih->saddr() = index;
	ih->daddr() = ipdst;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = NETWORK_DIAMETER;

	Scheduler::instance().schedule( target_, p, 0. );
	if( rt0->rt_flags>0 )
		rt0->rt_flags = RTF_VAILD ;
	
 #ifdef RREP_A
	rp->rp_RREP_A=true;
 #endif

	if( rp->rp_RREP_A )
	{
		rt0->rt_flags = RTF_ACK_WAITING;
		Scheduler::instance().schedule( &acktimer, p->copy(), RREP_ACK_WAIT_TIME );// if on ACK respons
	}

 #ifdef ShowAODViot_Packet_RREP_Send
printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf( GRN"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|S AODViot RREP |%d|%d|    Reserved     |Prefix Sz|  %10d   |\n",rp->rp_RREP_R,rp->rp_RREP_A,rp->rp_hop_count );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
 #ifdef Show_Packet_detail
printf( "|    Destination  IP      : %16d                    |\n",rp->rp_Dst_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Destination  SeqNo   : %16d                    |\n",rp->rp_Dst_Seqno );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|    Previous Hop IP      : %16d                    |\n",rp->rp_Prev_Hop_IP );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|        Life Time        :        %16.6f             |\n",rp->rp_lifetime );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 #endif
#endif
}

void AODViot::sendError( Packet *p, bool jitter ) {
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_error *re = HDR_AODViot_ERROR( p );
	RANDOM;
	#ifdef ERROR
	fprintf( stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock() );
	#endif // DEBUG

	re->re_type = AODViotTYPE_RERR;
	// re->reserved[0] = 0x00; re->reserved[1] = 0x00;
	// re_DestCount and list of unreachable destinations are already filled

	// ch->uid() = 0;
	ch->ptype() = PT_AODViot;
	ch->size() = IP_HDR_LEN + re->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->next_hop_ = 0;
	ch->prev_hop_ = index;			// AODViot hack
	ch->direction() = hdr_cmn::DOWN;		 //important: change the packet's direction

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = 1;

	// Do we need any jitter? Yes
	if( jitter )
		Scheduler::instance().schedule( target_, p, 0.01*Random::uniform() );
	else
		Scheduler::instance().schedule( target_, p, 0.0 );

#ifdef ShowAODViot_Packet_RERR_Send
printf( "\nTIME:%.9f Node:%d	IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
printf( RED"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
printf( "|S AODViot RERR |%d|          Reserved           |  %10d   |\n",re->re_RERR_N,re->re_DestCount );
printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
 #ifdef Show_Packet_detail
 for( int i = 0 ; i<re->re_DestCount ; i++ )
 {
	printf( "|Unreachable Destination  IP  :%32d |\n",re->re_unreachable_dst[i] );
	printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
	printf( "|Unreachable Destination SeqNo:%32d |\n",re->re_unreachable_dst_seqno[i] );
	printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
 }
 #endif
#endif
}

void AODViot::sendReply_ACK( nsaddr_t Prev_Hop ,nsaddr_t Org_IP ) {
	//Prev_Hop is the destination to next hop of route，( ack is send to the NEXT HOP of route )
#ifdef DEBUG
  fprintf( stderr, "Node %3d: sending Reply_ACK at %.2f ...", index, Scheduler::instance().clock() );
#endif // DEBUG

	/* NS2 SendRREP_ACK Initial */
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( 	p );
	struct hdr_aodvIot_rrep_ack *ra = HDR_AODViot_RREP_ACK( p );

	/* Packet Filling Phase( SendRREP_ACK ) */
	ra->rpack_type = AODViotTYPE_RREP_ACK;
	ra->rpack_Org_IP = Org_IP;

	ch->ptype() = PT_AODViot;
	ch->size() = IP_HDR_LEN + ra->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->prev_hop_ = index; // AODViot hack

	ih->saddr() = index;
	ih->daddr() = Prev_Hop;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = 1;

	/* Send Phase( SendRREP_ACK ) */
	Scheduler::instance().schedule( target_, p, 0.0 );

	/* End Phase( SendRREP_ACK ) */
#ifdef DEBUG
  fprintf( stderr, "Send!\n" );
#endif // DEBUG

#ifdef ShowAODViot_Packet_RREP_ACK_Send
  printf( "\nTIME:%.9f Node:%d   UDP/IP from %d to IP %d \n", CURRENT_TIME, index, ih->saddr(), ih->daddr() );
  printf( YEL"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
  printf( "|S AODViot RREP ACK|                  Reserved                  |\n" );
  printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"RST );
  #ifdef Show_Packet_detail
    printf( "+    Originator    IP    :    %8d                          |\n",ra->rpack_Org_IP );
    printf( "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" );
  #endif
#endif
}


/* Neighbor Management Functions */

void AODViot::sendHello() {
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN( p );
	struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_reply *rh = HDR_AODViot_REPLY( p );

	#ifdef DEBUG
	  fprintf( stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock() );
	#endif // DEBUG

	rh->rp_type = AODViotTYPE_HELLO;
	//rh->rp_flags = 0x00;
	rh->rp_hop_count = 1;
	rh->rp_Dst_IP = index;
	rh->rp_Dst_Seqno = seqno;
	rh->rp_lifetime = ( 1 + ALLOWED_HELLO_LOSS ) * HELLO_INTERVAL;

	// ch->uid() = 0;
	ch->ptype() = PT_AODViot;
	ch->size() = IP_HDR_LEN + rh->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->prev_hop_ = index;			// AODViot hack

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = 1;

	Scheduler::instance().schedule( target_, p, 0.0 );
}

void AODViot::recvHello( Packet *p ) {
	//struct hdr_ip *ih = HDR_IP( p );
	struct hdr_aodvIot_reply *rp = HDR_AODViot_REPLY( p );
	AODViot_Neighbor *nb;

	nb = nb_lookup( rp->rp_Dst_IP );

	if( nb == 0 )
		nb_insert( rp->rp_Dst_IP );
	else
		nb->nb_expire = CURRENT_TIME +( 1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL );

	Packet::free( p );
}

void AODViot::nb_insert( nsaddr_t id ) {
	AODViot_Neighbor *nb = new AODViot_Neighbor( id );

	assert( nb );
	nb->nb_expire = CURRENT_TIME + ( 1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL );
	LIST_INSERT_HEAD( &nbhead, nb, nb_link );
	seqno += 2;			 // set of neighbors changed
	assert ( ( seqno%2 ) == 0 );
}

AODViot_Neighbor* AODViot::nb_lookup( nsaddr_t id ) {
	AODViot_Neighbor *nb = nbhead.lh_first;

	for( ; nb; nb = nb->nb_link.le_next )
		if( nb->nb_addr == id )
			break;

	return nb;
}
// Called when we receive *explicit* notification that a Neighbor is no longer reachable.
void AODViot::nb_delete( nsaddr_t id ) {
	AODViot_Neighbor *nb = nbhead.lh_first;

	log_link_del( id );
	seqno += 2;	 // Set of neighbors changed
	assert ( ( seqno%2 ) == 0 );

	for( ; nb; nb = nb->nb_link.le_next ) {
		if( nb->nb_addr == id ) {
			LIST_REMOVE( nb,nb_link );
			delete nb;
			break;
		}
	}

	handle_link_failure( id );

}
// Purges all timed-out Neighbor Entries - runs every * HELLO_INTERVAL * 1.5 seconds.
void AODViot::nb_purge() {
	AODViot_Neighbor *nb = nbhead.lh_first;
	AODViot_Neighbor *nbn;
	double now = CURRENT_TIME;

	for( ; nb; nb = nbn ) {
		nbn = nb->nb_link.le_next;

		if( nb->nb_expire <= now )
			nb_delete( nb->nb_addr );
	}
}


//show helper
void AODViot::ShowRouteTable( nsaddr_t node ) {
	
	#define BLK "\x1b[;30;7m"
	#define sRS "\x1b[0;m" //same as RST
	aodvIot_rt_entry *RT = rtable.rt_lookup( node );
	if( !RT )
	{
		printf( "Destination TO %d is not in route table!!!\n",node );
		return;
	}
	
	printf( BLK"\n****************************************************************" );
	printf(   "\n**TIME:%13.9f ****Node:%3d RouteTable ****Lookup : %3d **",CURRENT_TIME,index,node );
	printf(   "\n****************************************************************"sRS );
	printf( "\n  Destination        :%d",RT->rt_dst );//nsaddr_t
	printf( "\n  Destination SeqNo  :%d",RT->rt_seqno );//u_int32_t
	// printf( "\n vaild_dst_seqno_flag:X" );
	printf( "\n        state        :%d ",RT->rt_flags );//u_int8_t
	switch( RT->rt_flags )
	{
		case 0:
			printf( "INVAILD" );
		break;
		case 1:
			printf( "VAILD" );
		break;
		case 2:
			printf( "RREP_WAITING" );
		break;
		case 3:
			printf( "ACK_WAITING" );
		break;
		case -1:
			printf( "BROADCASTING" );
		break;
		case -2:
			printf( "DISCOVERING" );
		break;
		case -3:
			printf( "BROADCAST_FINISHED" );
		break;		
		case -4:
			printf( "IN_REPAIR" );
		break;
	}
	
	// printf( "\n     rt_interface    :X" );//u_int8_t
	printf( "\n      hop count      :%d",RT->rt_hops );//u_int16_t
	printf( "\n       next hop      :%d",RT->rt_nexthop );//nsaddr_t
	// printf( "\n list of precursors  :X" );//
	printf( "\n rt_expire( lifetime? ):%f",RT->rt_expire );//double
	printf( "\n  rt_last_hop_count   :%d",RT->rt_last_hop_count );//int// last valid hop count
	printf( "\n****************************************************************\n\n" );
/*
#define RTF_ACK_WAITING			 3
#define RTF_RREP_WAITING		 2
#define RTF_VAILD				 1
//THE RTF >0 means the route is available.
#define RTF_INVAILD				 0
#define RTF_BROADCASTING		-1	//I broadcast RREQ ,I'm waiting to hear the same packet ,so i can make sure the RREQ have successfully been forward.
#define RTF_DISCOVERING			-2	//I have heard the same RREQ which i broadcast,now im sure broadcast is successfull.
#define RTF_BROADCAST_FINISHED	-3	//RREQ has finish re-broadcast ,I'm waiting RREP.
#define RTF_IN_REPAIR			-4
	*/
}
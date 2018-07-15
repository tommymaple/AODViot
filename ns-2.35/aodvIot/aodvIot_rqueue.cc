/*DiLiver Unicorn 2018*/

#include <assert.h>

#include <cmu-trace.h>
#include <aodvIot/aodvIot_rqueue.h>

#define CURRENT_TIME	Scheduler::instance().clock()
#define QDEBUG

/*
	Packet Queue used by AODViot.
*/

aodvIot_rqueue::aodvIot_rqueue() {
	head_ = tail_ = 0;
	len_ = 0;
	limit_ = AODViot_RTQ_MAX_LEN;
	timeout_ = AODViot_RTQ_TIMEOUT;
}

void
aodvIot_rqueue::enque( Packet *p ) {
struct hdr_cmn *ch = HDR_CMN( p );

 /*
	* Purge any packets that have timed out.
	*/
 purge();

 p->next_ = 0;
 ch->ts_ = CURRENT_TIME + timeout_;

 if( len_ == limit_ ) {
 Packet *p0 = remove_head();	// decrements len_

	 assert( p0 );
	 if( HDR_CMN( p0 )->ts_ > CURRENT_TIME ) {
	 drop( p0, DROP_RTR_QFULL );
	 }
	 else {
	 drop( p0, DROP_RTR_QTIMEOUT );
	 }
 }

 if( head_ == 0 ) {
	 head_ = tail_ = p;
 }
 else {
	 tail_->next_ = p;
	 tail_ = p;
 }
 len_++;
#ifdef QDEBUG
	 verifyQueue();
#endif // QDEBUG
}


Packet*
aodvIot_rqueue::deque() {
Packet *p;

 /*
	* Purge any packets that have timed out.
	*/
 purge();

 p = remove_head();
#ifdef QDEBUG
 verifyQueue();
#endif // QDEBUG
 return p;

}


Packet*
aodvIot_rqueue::deque( nsaddr_t dst ) {
Packet *p, *prev;

 /*
	* Purge any packets that have timed out.
	*/
 purge();

 findPacketWithDst( dst, p, prev );
 assert( p == 0 || ( p == head_ && prev == 0 ) || ( prev->next_ == p ) );

 if( p == 0 ) return 0;

 if( p == head_ ) {
	 p = remove_head();
 }
 else if( p == tail_ ) {
	 prev->next_ = 0;
	 tail_ = prev;
	 len_--;
 }
 else {
	 prev->next_ = p->next_;
	 len_--;
 }

#ifdef QDEBUG
 verifyQueue();
#endif // QDEBUG
 return p;

}

char
aodvIot_rqueue::find( nsaddr_t dst ) {
Packet *p, *prev;

 findPacketWithDst( dst, p, prev );
 if( 0 == p )
	 return 0;
 else
	 return 1;

}




/*
	Private Routines
*/

Packet*
aodvIot_rqueue::remove_head() {
Packet *p = head_;

 if( head_ == tail_ ) {
	 head_ = tail_ = 0;
 }
 else {
	 head_ = head_->next_;
 }

 if( p ) len_--;

 return p;

}

void
aodvIot_rqueue::findPacketWithDst( nsaddr_t dst, Packet*& p, Packet*& prev ) {

	p = prev = 0;
	for( p = head_; p; p = p->next_ ) {
		//		if( HDR_IP( p )->dst() == dst ) {
			 if( HDR_IP( p )->daddr() == dst ) {
		return;
	}
	prev = p;
	}
}


void
aodvIot_rqueue::verifyQueue() {
Packet *p, *prev = 0;
int cnt = 0;

 for( p = head_; p; p = p->next_ ) {
	 cnt++;
	 prev = p;
 }
 assert( cnt == len_ );
 assert( prev == tail_ );

}


/*
void
aodvIot_rqueue::purge() {
Packet *p;

 while( ( p = head_ ) && HDR_CMN( p )->ts_ < CURRENT_TIME ) {
	 // assert( p == remove_head() );
	 p = remove_head();
	 drop( p, DROP_RTR_QTIMEOUT );
 }

}
*/

bool
aodvIot_rqueue::findAgedPacket( Packet*& p, Packet*& prev ) {

	p = prev = 0;
	for( p = head_; p; p = p->next_ ) {
	if( HDR_CMN( p )->ts_ < CURRENT_TIME ) {
		return true;
	}
	prev = p;
	}
	return false;
}

void
aodvIot_rqueue::purge() {
Packet *p, *prev;

 while ( findAgedPacket( p, prev ) ) {
 	assert( p == 0 || ( p == head_ && prev == 0 ) || ( prev->next_ == p ) );

 	if( p == 0 ) return;

 	if( p == head_ ) {
	 		p = remove_head();
 	}
 	else if( p == tail_ ) {
	 		prev->next_ = 0;
	 		tail_ = prev;
	 		len_--;
 	}
 	else {
	 		prev->next_ = p->next_;
	 		len_--;
 	}
#ifdef QDEBUG
 	verifyQueue();
#endif // QDEBUG

	p = prev = 0;
 }

}


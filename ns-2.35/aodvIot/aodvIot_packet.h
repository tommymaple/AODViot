/*DiLiver Unicorn 2018 CopyLeft NothingRights. */
/*Ver1.3 Master Graduate Vertion 2018/JUY/07 */

#ifndef __aodvIot_packet_h__
#define __aodvIot_packet_h__

//#include <config.h>

#define AODViot_MAX_ERRORS 100

/** AODViot Packet Flags **/

// #define RREQ_G //gratuitous reply to RREQ destination. Highly recommend turn this on when using TCP link/applications. 
// #define RREQ_U //unknown Destination sequence numbers.
// #define RREQ_D //Destination reply only

// #define RREP_A

  /* This define turns on gratuitous replies- see aodvIot.cc for implementation contributed by
    Anant Utgikar, 09/16/02.*/

/* Packet Formats */
#define AODViotTYPE_RREQ		0x01
#define AODViotTYPE_RREP		0x02
#define AODViotTYPE_RERR		0x03
#define AODViotTYPE_RREP_ACK	0x04
#define AODViotTYPE_HELLO		0x05

/* AODViot Routing Protocol Header Macros */
#define HDR_AODViot( p )      ( ( struct hdr_aodvIot* )hdr_aodvIot::access( p ) )
#define HDR_AODViot_REQUEST( p )  ( ( struct hdr_aodvIot_request* )hdr_aodvIot::access( p ) )
#define HDR_AODViot_REPLY( p )  ( ( struct hdr_aodvIot_reply* )hdr_aodvIot::access( p ) )
#define HDR_AODViot_ERROR( p )  ( ( struct hdr_aodvIot_error* )hdr_aodvIot::access( p ) )
#define HDR_AODViot_RREP_ACK( p )  ( ( struct hdr_aodvIot_rrep_ack* )hdr_aodvIot::access( p ) )



/* General AODViot Header - shared by all formats */
struct hdr_aodvIot {
  u_int8_t    ah_type;
  // Header access methods
  static int offset_; // required by PacketHeaderManager
  inline static int& offset() { return offset_; }
  inline static hdr_aodvIot* access( const Packet* p ) { return ( hdr_aodvIot* ) p->access( offset_ ); }
};

struct hdr_aodvIot_request {
  u_int8_t    rq_type;    // Packet Type
  bool      rq_RREQ_J;    // flag J
  bool      rq_RREQ_R;    // flag R
  bool      rq_RREQ_G;    // flag G
  bool      rq_RREQ_D;    // flag D
  bool      rq_RREQ_U;    // flag U
  u_int8_t    reserved[1];
  u_int8_t    rq_hop_count;  // Hop Count
  nsaddr_t    rq_Dst_IP;    // Destination IP Address
  u_int32_t    rq_Dst_seqno;  // Destination Sequence Number
  nsaddr_t    rq_Org_IP;    // Originator IP Address //這是上一跳的IP位置
  u_int32_t    rq_Org_seqno;  // Originator Sequence Number
  double      rq_timestamp;  // when REQUEST sent; used to compute route discovery latency
  u_int32_t    rq_RREQ_ID;    // Broadcast ID ( Optional in AODViot )

  inline int size() {
    int sz = 0;
    //rq_timestamp is not include in packet

#ifdef RREQ_ID
  sz = 6*sizeof( u_int32_t );
#else
  sz = 5*sizeof( u_int32_t );
#endif

      assert ( sz >= 0 );
    return sz;
  }
};

struct hdr_aodvIot_reply {
  u_int8_t    rp_type;    // Packet Type
  bool      rp_RREP_R;    //flag R
  bool      rp_RREP_A;    //flag A
  u_int8_t    reserved[1];  //8bits 我改變預留位置位元 少1
  bool       Prefix_Sz[5];   //6bits 這邊多1
  u_int8_t    rp_hop_count;  // Hop Count
  nsaddr_t    rp_Dst_IP;    // Destination IP Address
  u_int32_t    rp_Dst_Seqno;  // Destination Sequence Number
  nsaddr_t    rp_Prev_Hop_IP;  // Previous Hop IP Address
  double      rp_lifetime;  // Lifetime
  double      rp_timestamp;  // when corresponding REQ sent; used to compute route discovery latency

  inline int size() {
    int sz = 0;
    //rp_timestamp is not include in packet

    sz = 5*sizeof( u_int32_t );
    assert ( sz >= 0 );
    return sz;
  }

};

struct hdr_aodvIot_error {
  u_int8_t    re_type;    // Type
  bool      re_RERR_N;    // flag N
  u_int8_t    reserved[2];  // Reserved
  u_int8_t    re_DestCount;  // re_DestCount
  // List of Unreachable destination IP addresses and sequence numbers
  nsaddr_t    re_unreachable_dst[AODViot_MAX_ERRORS];
  u_int32_t    re_unreachable_dst_seqno[AODViot_MAX_ERRORS];

  inline int size() {
    int sz = 0;
    /*
      sz = sizeof( u_int8_t )    // type
       + 2*sizeof( u_int8_t )   // reserved
       + sizeof( u_int8_t )    // length
       + length*sizeof( nsaddr_t ); // unreachable destinations
    */
    sz = ( re_DestCount*2 + 1 )*sizeof( u_int32_t );
    assert( sz );
    return sz;
  }

};

struct hdr_aodvIot_rrep_ack {

  u_int8_t  rpack_type;
  u_int8_t  reserved[3];
  nsaddr_t  rpack_Org_IP;  // Originator IP Address //this helps node knows which route's ack is it. 2018 X Rosh.

  inline int size() 
  { 
    int sz = 0;

    sz = 2*sizeof( u_int32_t );
    assert ( sz >= 0 );
    return sz;
  }
};

// for size calculation of header-space reservation
union hdr_all_aodvIot {
  hdr_aodvIot      ah;
  hdr_aodvIot_request  rreq;
  hdr_aodvIot_reply  rrep;
  hdr_aodvIot_error  rerr;
  hdr_aodvIot_rrep_ack rrep_ack;
};

#endif /* __aodvIot_packet_h__ */

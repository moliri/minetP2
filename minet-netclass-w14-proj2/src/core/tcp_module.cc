#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "minet_socket.h"

#include <string.h>
#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

using namespace std;

void die(int fd) {
    minet_close(fd);
    minet_deinit();
    exit(0);
}

//checks the incoming packet to make sure its in the acceptable
//sequence number range. returns true if fine, false otherwise
//from page 75 of rfc -jg
bool InSequence(TCPHeader tcph, TCPState state, unsigned len){
	unsigned int sequenceNum;
	tcph.GetSeqNum(sequenceNum);
	unsigned int next = state.last_recvd+len;
	
	//seg length 0, receive window 0 -jg
	if((len==0 && state.rwnd==0) && sequenceNum==next){
		return true;
	}
	//seg length 0, receive window > 0 -jg
	if(len==0 && (next <= sequenceNum) && (sequenceNum <= next+state.GetN())){
		return true;
	}
	//seg length >0, receive window 0 -jg
	if(len>0 && state.GetN() == 0){
		return false;
	}
	//seg length >0, receive window > 0 -jg
	if(len>0 && state.GetN() > 0){
		if((next <= sequenceNum) && (sequenceNum <= next+state.GetN())){
			return true;
		}
		if((next <= sequenceNum + len-1 )&& (sequenceNum + len-1 <= next+state.GetN())){
			return true;
		}
	}
	return false;
}

//if sequence is wrong for any states listed on rfc 75, make a packet
//with seq = send.next; ack = rcv.next, control = ack
Packet Unacceptable(Connection c,TCPHeader tcph, TCPState state, unsigned len){
	Packet p;
	IPHeader iph;
	TCPHeader th;
	  
	iph.SetProtocol(IP_PROTO_TCP);
	iph.SetSourceIP(c.src);
	iph.SetDestIP(c.dest);
	
	//push IP header onto packet
	p.PushFrontHeader(iph);
	
	th.SetSourcePort(c.srcport,p);
	th.SetDestPort(c.destport,p);
	
	//set sequence number = to send.next
	unsigned int seq;
	seq = state.GetLastSent();
	//only adding the base length since there isn't any payload with this packet-jg
	seq+=TCP_HEADER_BASE_LENGTH;
	th.SetSeqNum(seq,p);
	
	//set ack to recv.next
	unsigned int ack;
	tcph.GetAckNum(ack);
	ack+=TCP_HEADER_BASE_LENGTH;
	th.SetAckNum(ack,p);
	  
	//set the ack bit-jg
	unsigned char f = 0;
	th.GetFlags(f);
	SET_ACK(f);
	th.SetFlags(f,p);
	  
	//push it onto the packet-jg
	p.PushFrontHeader(th);
	
	return p;
}

int main(int argc, char *argv[])
{
  //i don't know if we should change these at all--jg
  MinetHandle mux, sock;

  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  cerr << "tcp_module handling tcp traffic.......\n";

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic........"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
		Packet p;
		bool checksumok;
		MinetReceive(mux,p);
		//GET TCP HEADER SIZE-jg
		//p.ExtractHeaderFromPayload<TCPHeader>(HEADER SIZE);
		TCPHeader tcph;
		tcph=p.FindHeader(Headers::TCPHeader);
		checksumok=tcph.IsCorrectChecksum(p);
		unsigned length = tcph.EstimateTCPHeaderLength(p);
		IPHeader iph;
		iph=p.FindHeader(Headers::IPHeader);
		Connection c;
		//upd_module says that "source" is interpreted as "this machine"
		//so this should be flipped
		iph.GetDestIP(c.src);
		iph.GetSourceIP(c.dest);

		iph.GetProtocol(c.protocol);

		tcph.GetDestPort(c.srcport);
		tcph.GetSourcePort(c.destport);

		//match ports and ips to existing connection
		//if no existing match, check flag for syn bit
		//if syn, make new connection, send syn ack
		//lookup ctags-jg
		ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
		if (cs!=clist.end()) {
			cerr << "State is " << cs->state.GetState();
			cerr << endl;
			bool correctSequence;
			if(InSequence(tcph,cs->state,length)){
				correctSequence = true;
			} else{
				correctSequence = false;
			}
			break;
			switch(cs->state.GetState()){
				case CLOSED:
					cerr << "Connection is closed...\n";
					return -1;
					break;
				case LISTEN:
						//put the seq num with connection, so
						//next packet is in order
						//send syn
						//send syn ack
						//change state to syn_rcvd	-jg
					break;
				case SYN_RCVD:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case SYN_SENT:
				case SYN_SENT1:
				case ESTABLISHED:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case SEND_DATA:
				case CLOSE_WAIT:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case FIN_WAIT1:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case CLOSING:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case LAST_ACK:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case FIN_WAIT2:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				case TIME_WAIT:
					if(!correctSequence){
						//do packet error stuff-jg
						MinetSend(mux, Unacceptable(c,tcph,cs->state,length));
						break;
					}
					break;
				default:
					cerr << "not implemented...\n";
					break;
			}
		}
		  /*len= TCPHeader::EstimateTCPHeaderLength(p);
		  cerr << "estimated header len="<<len<<"\n";
		  Buffer &data = p.GetPayload().ExtractFront(len);
		  SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);
		  
		  if (!checksumok) {
			MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
			}
			MinetSend(sock,write);
		} else {
			MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
			IPAddress source;
			iph.GetSourceIP(source);
			ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
			MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to hose"));
			MinetSend(mux, error);
		}
		cerr << "TCP Packet: IP Header is "<<iph<<" and ";
		cerr << "TCP Header is "<<tcph << " and ";
		cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
		
		//we have the tcp headers, so we should see what kind
		//of packet we have, then compare it to current connections
		//get the flags so we can test them
		

		char * f;
		tcph.GET_FLAGS(f);
		

		}*///-jg


	/*	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
		cerr << "estimated header len="<<tcphlen<<"\n";
		p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
		IPHeader ipl=p.FindHeader(Headers::IPHeader);
		TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

		cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
		cerr << "TCP Header is "<<tcph << " and ";
		cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
		
		  }*/
		  //  Data from the Sockets layer above  //
		  }
    if (event.handle==sock) {
		SockRequestResponse request;
		if(MinetReceive(sock,request)< 0){
			cerr << "Unable to receive Socket...\n";
			return -1;
		}
		  //following lines copied from lines 127-137 of udp_module.cc-jg
		  unsigned bytes = MIN_MACRO(TCP_HEADER_OPTION_MAX_LENGTH, request.data.GetSize());
		  Packet p(request.data.ExtractFront(bytes));

		  unsigned len = request.data.GetSize();//idea from buffer.h to get tcpheader size-jg
		  
		  //make IPHeader first-jg
		  IPHeader ih;
		  ih.SetProtocol(IP_PROTO_TCP);
		  ih.SetSourceIP(request.connection.src);
		  ih.SetDestIP(request.connection.dest);
		  ih.SetTotalLength(bytes+len+IP_HEADER_BASE_LENGTH);
		  // push it onto the packet
		  p.PushFrontHeader(ih);
		  
		  //iterator and mapping-jg
		  ConnectionList<TCPState>::iterator cs = clist.FindMatching(request.connection);
		  ConnectionToStateMapping<TCPState> mapping;
		  
		switch (request.type) {
		  case CONNECT:
		  {
			  //create socket-jg
			  sock = minet_socket(SOCK_STREAM);
			  if (sock < 0) {
				cerr << "Can't create socket." << endl;
				minet_perror("reason:");
				die(sock);
			  }
			  cerr << "Socket Created\n";
			  //send syn packet to IP layer to establish connection -jg
			    
				//now make TCPHeader-jg
				
			  TCPHeader th;
			  unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
			  cerr << "estimated header len="<<tcphlen<<"\n";
			  p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
			  
			  th.SetSourcePort(request.connection.srcport,p);
			  th.SetDestPort(request.connection.destport,p);
			  
			  //set the syn bit-jg
			  unsigned char f = 0;
			  th.GetFlags(f);
			  SET_SYN(f);
			  th.SetFlags(f,p);
			  
			  //push it onto the packet-jg
			  p.PushFrontHeader(th);
			  
			  //send packet to network layer-jg
			  MinetSend(mux,p);
			  
			  //make reply to send to socket-jg
			  SockRequestResponse reply;
			  reply.type=CONNECT;
			  reply.connection=request.connection;
			  reply.bytes=bytes;
			  reply.error=EOK;
			  MinetSend(sock,reply);
			  
			  //change state to syn-sent-jg
			  cs->state.SetState(SYN_SENT);
			break;
		}
		  case ACCEPT:
		  {
			  //create a connection and put into clist-jg
			  mapping.connection=request.connection;
			  
			  //before adding, check if there is already this connection-jg
			  if (cs!=clist.end()){
					//if there is a connection, we can't accept one that is here-jg
					SockRequestResponse reply;
					reply.type=STATUS;
					reply.error=ERESOURCE_UNAVAIL;
					MinetSend(sock,reply);
					break;
			  }
			  //add the connection to the list.-jg
			  clist.push_back(mapping);
			
				SockRequestResponse reply;
				reply.type=ACCEPT;
				reply.connection=request.connection;
				reply.bytes=bytes;
				reply.error=EOK;
				MinetSend(sock,reply);
				
				break;
			}
		  case STATUS:
		  case WRITE:
		  //send out the packet to the designated connection in clist-jg
		  case FORWARD:
		  case CLOSE:
		  //send fin bit -jg
		  //change state-jg
		  default:
			SockRequestResponse reply;
			reply.type=STATUS;
			reply.error=EWHAT;
			MinetSend(sock,reply);

			cerr << "Received Socket Request:" << request << endl;
			break;
        }
      }
    }
  }
  return 0;
}

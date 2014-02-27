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

//what to do if there is a syn in a wrong state (syn-rcvd->closing)
void badSyn(unsigned char flag,Packet p,unsigned int ackNum, TCPHeader th,MinetHandle mux,ConnectionList<TCPState>::iterator cs){
		//send reset packet-jg
		SET_RST(flag);
		th.SetSeqNum(ackNum,p);
		th.SetFlags(flag,p);
		p.PushFrontHeader(th);
		MinetSend(mux,p);
		//reset connection-jg
		MinetSendToMonitor(MinetMonitoringEvent("error: connection reset"));
		cs->state.SetState(CLOSED);
}

//to more easily test for the flags required for states syn-rcvd-->closing
bool checkFlags(unsigned tcpLength,bool inSequence, unsigned char oldF, unsigned char newF, Packet p, unsigned int ackNum, TCPHeader oldth, TCPHeader newth, MinetHandle mux, Connection c, ConnectionList<TCPState>::iterator cs){
	if(!inSequence){
		//do packet error stuff-jg
		MinetSend(mux, Unacceptable(c,oldth,cs->state,tcpLength));
		return false;
	}
	//if reset is set, go to closed state-jg
	if(IS_RST(oldF)){
		cs->state.SetState(CLOSED);
		return false;
	}
	if(IS_SYN(oldF)){
		//send reset and reset connection -jg
		badSyn(newF,p,ackNum,newth,mux,cs);
		return false;
	}
	if(!IS_ACK(oldF)){
		//drop segment and return-jg
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
  //i don't know if we should change these at all--jg
  //looks like mux is not initialized properly, looking into it -lm
  MinetHandle mux, sock;

  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
	cerr << "can't connect to ip_mux \n"; //debug - lm
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
	cerr << "can't accept from SOCK module \n";  //debug - lm
    return -1;
  }

  cerr << "tcp_module handling tcp traffic.......\n";

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic........"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
	cerr << "are we in the while loop? \n";
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } 
	else {
      //  Data from the IP layer below  //
	  cerr << "event.handle is " << event.handle << endl;  //debug, event.handle=1 and mux=0, never enter the mux if statement - lm
	  cerr << "mux is " << mux << endl;
      if (event.handle==mux) {
		Packet p;
		bool checksumok;
		MinetReceive(mux,p);
		cerr << "MinetReceive successful \n"; //debug - lm
		
		//GET TCP HEADER SIZE-jg
		//p.ExtractHeaderFromPayload<TCPHeader>(HEADER SIZE);
		TCPHeader tcph;
		tcph=p.FindHeader(Headers::TCPHeader);
		unsigned tcpLength = tcph.EstimateTCPHeaderLength(p);
		p.ExtractHeaderFromPayload(Headers::TCPHeader,tcpLength);
		checksumok=tcph.IsCorrectChecksum(p);
		
		cerr << "TCP header size obtained \n"; //debug - lm
		
		//get ip total length for calculation of data size-jg
		IPHeader iph;
		iph=p.FindHeader(Headers::IPHeader);
		unsigned short totalLength;
		iph.GetTotalLength(totalLength);
		unsigned char ipLength;
		iph.GetHeaderLength(ipLength);
		
		//thanks to discussion board post by eric lin-jg
		unsigned dataLength = totalLength - ipLength - tcpLength;
		
		cerr << "total length is " << totalLength << endl; //debug - lm
		cerr << "data length is " << dataLength << endl; //debug - lm
		
		Connection c;
		//upd_module says that "source" is interpreted as "this machine"
		//so this should be flipped
		cerr << "Dest IP is" << c.src << endl; //double checking src/dest IP adds -lm
		cerr << "Src IP is" << c.dest << endl;
		iph.GetDestIP(c.src);
		iph.GetSourceIP(c.dest);

		iph.GetProtocol(c.protocol);

		tcph.GetDestPort(c.srcport);
		tcph.GetSourcePort(c.destport);
		
		Packet p2;
		IPHeader ih;
		TCPHeader th;
		  
		ih.SetProtocol(IP_PROTO_TCP);
		ih.SetSourceIP(c.src);
		ih.SetDestIP(c.dest);
		
		//push IP header onto packet-jg
		p2.PushFrontHeader(ih);
		
		//get control flags-jg
		unsigned char oldF,newF = 0;
		tcph.GetFlags(oldF);
		
		//set src and dst ports for tcp header-jg
		th.SetSourcePort(c.srcport,p2);
		th.SetDestPort(c.destport,p2);
		
		unsigned int seqNum;
		tcph.GetSeqNum(seqNum);
		unsigned int ackNum;
		tcph.GetAckNum(ackNum);
		unsigned int seqLen = tcph.EstimateTCPHeaderLength(p);

		//match ports and ips to existing connection
		//if no existing match, check flag for syn bit
		//if syn, make new connection, send syn ack
		//lookup ctags-jg
		
		ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
			cerr << "State is " << cs->state.GetState();
			cerr << endl;
			bool inSequence;
			inSequence = InSequence(tcph,cs->state,tcpLength);
			unsigned int ISS = rand()%(2<< cs->state.GetN());
		if (cs!=clist.end()) {
			switch(cs->state.GetState()){
				case CLOSED:
				{
					//rfc page 65
					//if ack bit is off, seq num 0 is used and ack with ack num seq+seq.len-jg
					//reset and ack fields of control flag set-jg
					if (!IS_ACK(oldF)){
						th.SetSeqNum(0,p2);
						th.SetAckNum(seqNum+seqLen,p2);
						SET_ACK(newF);
						SET_RST(newF);
					}
					//if ack bit is on, seq num of segment's ack is used, no ack sent-jg
					//rset field set for control flag-jg
					else {
						th.SetSeqNum(ackNum,p2);
						SET_RST(newF);
					}
					th.SetFlags(newF,p2);
					p2.PushFrontHeader(th);
					MinetSend(mux,p2);
					if(IS_FIN(oldF)){
						break;
					}
					break;
				}
				case LISTEN:
				{
					//rfc pg 65
					//check for rst. if there is one, ignore it and return-jg
					if (IS_RST(oldF)){
						break;
					}
					//check for ack. form reset with seq=seg.ack and control=rest-jg
					if (IS_ACK(oldF)){
						th.SetSeqNum(ackNum,p2);
						SET_RST(newF);
						th.SetFlags(newF,p2);
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
					}
					
					//check for syn.//ARE WE DOING SECURITY STUFF?
					if (IS_SYN(oldF)){
						//set recv.next to seg.seq+1.
							//is there a recv.next in our tcpstate.h?-jg
						//set initial received sequence number to seg.seq
						cs->state.SetLastRecvd(seqNum);
						//MAKE SYN: set seq to iss(make a new one)
						th.SetSeqNum(ISS,p2);
						//set ack to rcv.next, control to syn,ack
						SET_SYN(newF);
						SET_ACK(newF);
						th.SetFlags(newF,p2);
						th.SetAckNum(seqNum+1,p2);//same as above-jg
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
						//set send.next to iss+1 and send.una to ISS
						cs->state.SetLastSent(ISS+1);
						//no unacked, so set last acked to ISS-1?-jg
						cs->state.SetLastAcked(ISS-1);
						//change state to syn-received
						cs->state.SetState(SYN_RCVD);
						break;
					}
					if(IS_FIN(oldF)){
						break;
					}
					break;
				}
				case SYN_SENT:
				{
					//if ack is set and <= ISS or > send.next and !reset, send reset
					//with seq=seg.ack and ctrl = reset--jg

					if (IS_ACK(oldF) && 
							((ackNum <= ISS) || ( ackNum > cs->state.GetLastSent())) &&
							(!IS_RST(oldF))){
								//send reset with seq=seg.ack and ctrl= reset-jg
								SET_RST(newF);
								th.SetSeqNum(ackNum,p2);
								th.SetFlags(newF,p2);
								p2.PushFrontHeader(th);
								MinetSend(mux,p2);
								break;
					}
					//if the ack is acceptable and reset is set-jg
					else if (inSequence && IS_RST(oldF)){
						//this is a connection reset
						MinetSendToMonitor(MinetMonitoringEvent("error: connection reset"));
						cs->state.SetState(CLOSED);
						break;
					}
					//if there is either no ack, or the ack is acceptable-jg
					if (!IS_ACK(oldF) || inSequence){
						if (IS_SYN(oldF)){
							//rcv.nxt = seg.seq+1-jg
							cs->state.SetLastRecvd(seqNum);
							//IRS=seg.seq-jg
							//there doesn't appear to be one in tcpstate...-jg
							//(if there is an ack): snd.una=seg.ack -jg
							//if snd.una < iss, set state to established, and form ack statement:
								//seq=send.nxt, ack=rcv.nxt, ctl=ack and send-jg
							if(cs->state.GetLastAcked() + 1 < ISS){
								cs->state.SetState(ESTABLISHED);
								SET_ACK(newF);
								th.SetSeqNum(ISS,p2);
								th.SetAckNum(seqNum+1,p2);
								th.SetFlags(newF,p2);
								p2.PushFrontHeader(th);
								MinetSend(mux,p2);
								break;
							}
							//else set state to syn-received, and form a syn,ack segment:
								//seq=iss, ack=rcv.nxt,ctrl=ack,syn and send-jg
							else {
								cs->state.SetState(SYN_RCVD);
								SET_ACK(newF);
								SET_SYN(newF);
								th.SetFlags(newF,p2);
								th.SetAckNum(seqNum+1,p2);
								th.SetSeqNum(ISS,p2);
								p2.PushFrontHeader(th);
								MinetSend(mux,p2);
								break;
							}
						}
					}
					//if the ack is wrong and reset, ignore-jg
					if (IS_RST(oldF) || IS_FIN(oldF)){
						break;
					}
					break;
					
				}
				//Otherwise, first check the seq-num:pg 69-jg
				case SYN_RCVD:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if send.unacked <= seg.ack <= send.next, then enter established state
						cs->state.SetState(ESTABLISHED);
						break;
					}
					if(IS_FIN(oldF)){
						CLR_ACK(newF); //get rid of any ack that data would have sent
						th.SetSeqNum(cs->state.GetLastSent()+1,p2);
						th.SetAckNum(seqNum,p2);
						th.SetFlags(newF,p2);
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
						cs->state.SetState(CLOSE_WAIT);
						break;
					}
					break;
				}
				case ESTABLISHED:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if acceptable, set last acked to seq.ack
						cs->state.SetLastAcked(ackNum);
						//update sender window
						unsigned short segWin;
						tcph.GetWinSize(segWin);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+segWin);
					}
					//to get data, have length of data, length of ipheader, length of tcpheader
					//should just be able to make a buffer and store payload there
					//then move char * to ipheader length + tcpheader length
					//then copy all of the next totalLength bytes into new buffer-jg
					if (dataLength > 0){
						char *tmp = new char[totalLength];
						char *data = new char[dataLength];
						//all data in buffer
						p.DupeRaw(tmp,totalLength);
						tmp+=ipLength;
						tmp+=tcpLength;
						//should be pointing at start of data now-jg
						while(tmp!=tmp+totalLength){
							*data = *tmp;
							data++;
							tmp++;
						}
						//should have only application data in data buf now
						//can send to socket, but not mux socket. have to send to sock-jg
						int write = minet_write(sock,data,totalLength);
						if(write < 0){
							MinetSendToMonitor(MinetMonitoringEvent("error: data not sent to hose"));
							break;
						}		
						//adjust receiving window and next expected packet-jg
						cs->state.SetLastRecvd(seqNum);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+totalLength);
						
						//send ack with seq=send.next, ack=recv.next,ctrl=ack-jg
						SET_ACK(newF);
						th.SetSeqNum(cs->state.GetLastSent()+1,p2);
						th.SetAckNum(seqNum,p2);
						th.SetFlags(newF,p2);
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
					}
					
					//if fin is set, tell application that its closing-jg
					//send ack for the fin
					if(IS_FIN(oldF)){
						CLR_ACK(newF); //get rid of any ack that data would have sent
						th.SetSeqNum(cs->state.GetLastSent()+1,p2);
						th.SetAckNum(seqNum,p2);
						th.SetFlags(newF,p2);
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
						cs->state.SetState(CLOSE_WAIT);
					}
					
					break;
				}
				case FIN_WAIT1:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if acceptable, set last acked to seq.ack
						cs->state.SetLastAcked(ackNum);
						//update sender window
						unsigned short segWin;
						tcph.GetWinSize(segWin);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+segWin);
						if(IS_FIN(oldF)){
							cs->state.SetState(FIN_WAIT2);
						}
					}
					if(IS_FIN(oldF)){
						//enter time-wait-jg
						cs->state.SetState(TIME_WAIT);
						//ignoring timer stuff for now
						break;
					}
					break;
				}
				case FIN_WAIT2:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if acceptable, set last acked to seq.ack
						cs->state.SetLastAcked(ackNum);
						//update sender window
						unsigned short segWin;
						tcph.GetWinSize(segWin);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+segWin);
					}
					if(IS_FIN(oldF)){
						cs->state.SetState(TIME_WAIT);
						break;
					}
					break;
				}
				case CLOSE_WAIT:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if acceptable, set last acked to seq.ack
						cs->state.SetLastAcked(ackNum);
						//update sender window
						unsigned short segWin;
						tcph.GetWinSize(segWin);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+segWin);
					}
					break;
				}
				
				case CLOSING:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_ACK(oldF)){
						//if acceptable, set last acked to seq.ack
						cs->state.SetLastAcked(ackNum);
						//update sender window
						unsigned short segWin;
						tcph.GetWinSize(segWin);
						cs->state.SetSendRwnd(cs->state.GetRwnd()+segWin);
						if(IS_FIN(oldF)){
							cs->state.SetState(TIME_WAIT);
						}
					}
					break;
				}
				case LAST_ACK:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_FIN(oldF)&&(IS_ACK(oldF))){
						cs->state.SetState(CLOSED);
					}
					break;
				}
				case TIME_WAIT:
				{
					if(!checkFlags(tcpLength,inSequence,oldF,newF,p2,ackNum,tcph,th,mux,c,cs)){
						break;
					}
					if(IS_FIN(oldF)){
						//acknowledge the fin and restart msl
						th.SetAckNum(seqNum+1,p2);
						th.SetSeqNum(ackNum+1,p2);
						SET_ACK(newF);
						SET_FIN(newF);
						th.SetFlags(newF,p2);
						p2.PushFrontHeader(th);
						MinetSend(mux,p2);
						break;
					}
					break;
				}
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
	  cerr << "event.handle is " << event.handle << endl;  //debug, event.handle=1 and sock=1, enter the sock if statement - lm
	  cerr << "sock is " << sock << endl;
	  if (event.handle==sock) {
		SockRequestResponse request;
		if(MinetReceive(sock,request)< 0){
			cerr << "Unable to receive Socket...\n";
			return -1;
		}
		  //following lines copied from lines 127-137 of udp_module.cc-jg
		  //likely need to modify this, bytes and length are 0 and packet looks empty - lm
		  unsigned bytes = MIN_MACRO(TCP_HEADER_OPTION_MAX_LENGTH, request.data.GetSize());
		  Packet p(request.data.ExtractFront(bytes));

		  unsigned len = request.data.GetSize();//idea from buffer.h to get tcpheader size-jg
		  
		  //debug, checking values - lm
		  cerr << "bytes is " << bytes <<endl; //0
		  cerr << "packet is " << p <<endl; //Packet(headers={}, payload=Buffer(size=0, data= , text=""), trailers={})
		  cerr << "length is " << len <<endl; //0
		  
		  
		  
		  //make IPHeader first-jg
		  IPHeader ih;
		  ih.SetProtocol(IP_PROTO_TCP); //worked -lm
		  ih.SetSourceIP(request.connection.src); //worked -lm
		  ih.SetDestIP(request.connection.dest);  //not set? see Header comment below -lm
		  ih.SetTotalLength(bytes+len+IP_HEADER_BASE_LENGTH); //length not updated - lm
		  // push it onto the packet
		  p.PushFrontHeader(ih); //header not updated correctly, see comment below - lm
		  
		  //debug, checking values - lm
		  cerr << "IP Header is " << ih <<endl; //IPHeader( version=4, hlen=5 (20), tos=0, len=20, id=1, flags=2(DO NOT FRAGMENT NO MORE FRAGMENTS), fragoff=0, ttl=64, proto=6(TCP), checksum=8899(valid), computedchecksum=0, src=IPAddress(10.10.14.23), dst=IPAddress(0.0.0.0)noopts) 
		  cerr << "bytes is now " << bytes <<endl; //0
		  cerr << "packet is now " << p <<endl; //Packet(headers={TaggedBuffer(tag=IPHeader, Buffer(size=20, data=45...etc, text="E+++++@+@" "++++++++")}, payload=Buffer(size=0, data=, text=""), trailers={}) 
		  cerr << "length is now " << len <<endl; //0
		  
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

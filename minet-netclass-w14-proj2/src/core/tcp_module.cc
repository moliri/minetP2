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

#include <string.h>
#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

struct TCPState {
  std::ostream & Print(std::ostream &os) const { os << "TCPState()"; return os;}

  friend std::ostream &operator<<(std::ostream &os, const TCPState& L) {
		return L.Print(os);
  }
};

int main(int argc, char *argv[])
{
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
	unsigned short len;
	bool checksumok;
	MinetReceive(mux,p);
	p.ExtractHeaderFromPayload<TCPHeader>(8);
	TCPHeader tcph;
	tcph=p.FindHeader(Headers::TCPHeader);
	checksumok=tcph.IsCorrectChecksum(p);
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

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
	if (cs!=clist.end()) {
	  len= TCPHeader::EstimateTCPHeaderLength(p);
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
	}

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
      if (event.handle==sock) {
	SockRequestResponse s;
	MinetReceive(sock,s);
	cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}

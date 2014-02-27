README for TCP Project of Networking 340, winter 2014
Jordan Geltner (jmg920), "-jg" in code
Leesha Maliakal (lvm908), "lm" in code

work by each member:

jmg920:
	-wrote tcp and ip header manipulation code in (event.handle=mux) case
	-wrote method InSequence, to check if the packet is acceptable
	-wrote method Unaccetpable, which returns a packet to be sent in unacceptable cases
	-wrote method badSyn, which handles the case of an erroneously received syn bit
	-wrote method checkFlags, which combines several checks that are the same for state SYN_RCVD to CLOSING
	-followed RFC 793's definition (as best as able) to implement TCP in switch(cs->state.GetState())
	-wrote cases ACCEPT, CONNECT, and default for socket events

lvm908:
	
package fr.pantheonsorbonne.cri;

class Event {

	public Event() {
	};

	@Override
	public String toString() {
		return "Event [event=" + event + ", table=" + table + ", icmp=" + icmp + ", reason=" + reason + ", arp=" + arp
				+ ", in_port=" + in_port + ", dl_src=" + dl_src + ", dl_dst=" + dl_dst + ", arp_spa=" + arp_spa
				+ ", arp_tpa=" + arp_tpa + ", arp_op=" + arp_op + ", nw_tos=" + nw_tos + ", icmp_type=" + icmp_type
				+ ", icmp_code=" + icmp_code + ", actions=" + actions + ", getClass()=" + getClass() + ", hashCode()="
				+ hashCode() + ", toString()=" + super.toString() + "]";
	}

	String event;
	int table = -1;
	boolean icmp = false;
	String reason = "";
	boolean arp = false;
	int in_port = -1;
	String dl_src;
	String dl_dst;
	String arp_spa;
	String arp_tpa;
	int arp_op = -1;
	int nw_tos = -1;
	int icmp_type = -1;
	int icmp_code = -1;
	String actions;
}
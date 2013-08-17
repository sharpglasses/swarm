#include <gtest/gtest.h>
#include <pcap.h>

#include "swarm.h"

class Counter  : public swarm::Handler {
protected:
  int count_;
public:
  Counter () : count_(0) {}
  int count () const { 
    return this->count_; 
  }
};

class EtherHandler : public Counter {
private:
  swarm::param_id src_;

public:
  EtherHandler (swarm::NetDec * nd) {
    this->src_ = nd->lookup_param_id ("eth.src");
    EXPECT_NE (swarm::PARAM_NULL, this->src_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    const swarm::Param * p = prop.param (this->src_);
    EXPECT_TRUE (p != NULL);
  }
};

class IPv4Handler : public Counter {
private:
  swarm::param_id src_;

public:
  IPv4Handler (swarm::NetDec * nd) {
    this->src_ = nd->lookup_param_id ("ipv4.src");
    EXPECT_NE (swarm::PARAM_NULL, this->src_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    const swarm::Param * p = prop.param (this->src_);
    EXPECT_TRUE (p != NULL);
  }
};

class DnsHandler : public Counter {
private:
  swarm::param_id type_;

public:
  DnsHandler (swarm::NetDec * nd) {
    this->type_ = nd->lookup_param_id ("dns.type");
    EXPECT_NE (swarm::PARAM_NULL, this->type_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    const swarm::Param * p = prop.param (this->type_);
    EXPECT_TRUE (p != NULL);
  }
};


TEST (NetDec, param) {
  swarm::NetDec *nd = new swarm::NetDec ();
  swarm::param_id p_blue   = nd->assign_param ("blue");
  swarm::param_id p_orange = nd->assign_param ("orange");

  EXPECT_NE (swarm::PARAM_NULL, p_blue);
  EXPECT_NE (swarm::PARAM_NULL, p_orange);
  EXPECT_NE (p_blue, p_orange);

  EXPECT_EQ (p_blue,   nd->lookup_param_id ("blue"));
  EXPECT_EQ (p_orange, nd->lookup_param_id ("orange"));
  EXPECT_EQ (swarm::EV_NULL, nd->lookup_param_id ("red"));

  EXPECT_EQ ("blue",   nd->lookup_param_name (p_blue));
  EXPECT_EQ ("orange", nd->lookup_param_name (p_orange));
  delete nd;
}

TEST (NetDec, event) {
  swarm::NetDec *nd = new swarm::NetDec ();
  swarm::ev_id p_blue   = nd->assign_event ("blue");
  swarm::ev_id p_orange = nd->assign_event ("orange");

  EXPECT_NE (swarm::EV_NULL, p_blue);
  EXPECT_NE (swarm::EV_NULL, p_orange);
  EXPECT_NE (p_blue, p_orange);

  EXPECT_EQ (p_blue,   nd->lookup_ev_id ("blue"));
  EXPECT_EQ (p_orange, nd->lookup_ev_id ("orange"));
  EXPECT_EQ (swarm::EV_NULL, nd->lookup_ev_id ("red"));

  EXPECT_EQ ("blue",   nd->lookup_ev_name (p_blue));
  EXPECT_EQ ("orange", nd->lookup_ev_name (p_orange));
  delete nd;
}

TEST (NetDec, handler) {
  swarm::NetDec *nd = new swarm::NetDec ();
  EtherHandler * eth_h = new EtherHandler (nd);
  IPv4Handler * ip4_h = new IPv4Handler (nd);
  
  swarm::ev_id eth_ev  = nd->lookup_ev_id ("ether.packet");
  swarm::ev_id ip4_ev = nd->lookup_ev_id ("ipv4.packet");

  swarm::hdlr_id eth_hdlr = nd->set_handler (eth_ev, eth_h);
  swarm::hdlr_id ip4_hdlr = nd->set_handler (ip4_ev, ip4_h);
  
  EXPECT_NE (swarm::HDLR_NULL, eth_hdlr);
  EXPECT_NE (swarm::HDLR_NULL, ip4_hdlr);
  EXPECT_NE (eth_hdlr, ip4_hdlr);

  EXPECT_EQ (true,  nd->unset_handler (eth_hdlr));
  EXPECT_EQ (false, nd->unset_handler (eth_hdlr));
  EXPECT_EQ (true,  nd->unset_handler (ip4_hdlr));
  EXPECT_EQ (false, nd->unset_handler (ip4_hdlr));
}

TEST (NetDec, basic_scenario) {
  swarm::NetDec *nd = new swarm::NetDec ();
  DnsHandler * dns_h = new DnsHandler (nd);
  EtherHandler * eth_h = new EtherHandler (nd);
  IPv4Handler * ip4_h = new IPv4Handler (nd);

  swarm::ev_id eth_ev  = nd->lookup_ev_id ("ether.packet");
  swarm::ev_id ip4_ev = nd->lookup_ev_id ("ipv4.packet");
  swarm::ev_id dns_ev  = nd->lookup_ev_id ("dns.packet");

  swarm::hdlr_id eth_hdlr = nd->set_handler (eth_ev, eth_h);
  swarm::hdlr_id ip4_hdlr = nd->set_handler (ip4_ev, ip4_h);
  swarm::hdlr_id dns_hdlr = nd->set_handler (dns_ev, dns_h);

  EXPECT_NE (swarm::EV_NULL, eth_ev);
  EXPECT_NE (swarm::EV_NULL, ip4_ev);
  EXPECT_NE (swarm::EV_NULL, dns_ev);

  EXPECT_NE (swarm::HDLR_NULL, eth_hdlr);
  EXPECT_NE (swarm::HDLR_NULL, ip4_hdlr);
  EXPECT_NE (swarm::HDLR_NULL, dns_hdlr);

  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string sample_file = "./data/SkypeIRC.cap";
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  pd = pcap_open_offline(sample_file.c_str (), errbuf);
  ASSERT_TRUE (pd != NULL);

  int dlt = pcap_datalink (pd);
  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts, dlt);
  }

  EXPECT_EQ ( 707, dns_h->count ());
  EXPECT_EQ (2247, dns_h->count ());
  EXPECT_EQ (2263, eth_h->count ());

  delete nd;
  delete eth_h;
  delete ip4_h;
  delete dns_h;
}

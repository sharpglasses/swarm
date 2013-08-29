/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <gtest/gtest.h>
#include <pcap.h>

#include "../src/swarm.h"

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
  explicit EtherHandler (swarm::NetDec * nd) {
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
  explicit IPv4Handler (swarm::NetDec * nd) {
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
  explicit DnsHandler (swarm::NetDec * nd) {
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
  
  EXPECT_EQ (0, nd->param_size ());
  swarm::param_id p_blue   = nd->assign_param ("blue");
  EXPECT_EQ (1, nd->param_size ());
  swarm::param_id p_orange = nd->assign_param ("orange");
  EXPECT_EQ (2, nd->param_size ());

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

  EXPECT_EQ (0, nd->event_size ());
  swarm::ev_id p_blue   = nd->assign_event ("blue");
  EXPECT_EQ (1, nd->event_size ());
  swarm::ev_id p_orange = nd->assign_event ("orange");
  EXPECT_EQ (2, nd->event_size ());

  EXPECT_NE (swarm::EV_NULL, p_blue);
  EXPECT_NE (swarm::EV_NULL, p_orange);
  EXPECT_NE (p_blue, p_orange);

  EXPECT_EQ (p_blue,   nd->lookup_event_id ("blue"));
  EXPECT_EQ (p_orange, nd->lookup_event_id ("orange"));
  EXPECT_EQ (swarm::EV_NULL, nd->lookup_event_id ("red"));

  EXPECT_EQ ("blue",   nd->lookup_event_name (p_blue));
  EXPECT_EQ ("orange", nd->lookup_event_name (p_orange));
  delete nd;
}

TEST (NetDec, handler) {
  swarm::NetDec *nd = new swarm::NetDec ();
  EtherHandler * eth_h = new EtherHandler (nd);
  IPv4Handler * ip4_h = new IPv4Handler (nd);
  
  swarm::ev_id eth_ev  = nd->lookup_event_id ("ether.packet");
  swarm::ev_id ip4_ev = nd->lookup_event_id ("ipv4.packet");

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

  swarm::ev_id eth_ev  = nd->lookup_event_id ("ether.packet");
  swarm::ev_id ip4_ev = nd->lookup_event_id ("ipv4.packet");
  swarm::ev_id dns_ev  = nd->lookup_event_id ("dns.packet");

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

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

#include <stdint.h>
#include <pcap.h>
#include <swarm.h>
#include <map>

class Flow {
 private:
  uint64_t len_;
  uint64_t pkt_;
  std::string proto_;

 public:
  explicit Flow (const std::string &proto) : len_(0), pkt_(0), proto_(proto) {
  }
  void recv_pkt (size_t len) {
    this->len_ += len;
    this->pkt_ += 1;
  }
  uint64_t len () const {
    return this->len_;
  }
  uint64_t pkt () const {
    return this->pkt_;
  }
  const std::string & proto () const {
    return this->proto_;
  }
};

class FlowHandler : public swarm::Handler {
 private:
  std::map <u_int64_t, Flow *> flow_map_;
  swarm::ev_id tcp_, udp_;

 public:
  void set_eid (swarm::ev_id tcp, swarm::ev_id udp) {
    this->tcp_ = tcp;
    this->udp_ = udp;
  }
  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    u_int64_t hv = p.get_5tuple_hash ();
    std::string proto = p.param ("ipv4.proto")->repr ();

    auto it = this->flow_map_.find (hv);
    Flow * f = NULL;
    if (it == this->flow_map_.end ()) {
      f = new Flow (proto);
      this->flow_map_.insert (std::make_pair (hv, f));
    } else {
      f = it->second;
    }

    f->recv_pkt (p.org_len ());
  }
  void dump () {
    for (auto it = this->flow_map_.begin ();
         it != this->flow_map_.end (); it++) {
      Flow * f = it->second;
      printf ("%016llX, %s, %lld, %lld\n",
              it->first, f->proto ().c_str (), f->len (), f->pkt ());
    }
  }
};

void read_pcapfile (const std::string &fpath) {
  // ----------------------------------------------
  // setup pcap file
  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];

  pd = pcap_open_offline(fpath.c_str (), errbuf);
  if (pd == NULL) {
    printf ("error: %s\n", errbuf);
    return;
  }
  int dlt = pcap_datalink (pd);


  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  FlowHandler * fh = new FlowHandler ();
  nd->set_handler ("ipv4.packet", fh);

  // ----------------------------------------------
  // processing packets from pcap file
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts, dlt);
  }

  fh->dump ();
  return;
}

int main (int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    read_pcapfile (std::string (argv[i]));
  }
}
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
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/time.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <swarm.h>
#include <map>
#include <vector>

#include "./optparse.h"

class Flow {
 private:
  uint64_t len_;
  uint64_t pkt_;
  std::string proto_;
  struct timeval tv_start_, tv_end_;

  static inline double tv2d (const struct timeval &tv) {
    return static_cast <double> (tv.tv_sec) +
      static_cast <double> (tv.tv_usec) / 1000000;
  }

 public:
  explicit Flow(const std::string &proto) : len_(0), pkt_(0), proto_(proto) {
  }
  void recv_pkt(size_t len, struct timeval *tv) {
    if (this->pkt_ == 0) {
      ::memcpy (&(this->tv_start_), tv, sizeof (this->tv_start_));
    }

    ::memcpy (&(this->tv_end_), tv, sizeof (this->tv_end_));
    this->len_ += len;
    this->pkt_ += 1;
  }
  uint64_t len() const {
    return this->len_;
  }
  uint64_t pkt() const {
    return this->pkt_;
  }
  const std::string & proto() const {
    return this->proto_;
  }
  double ts () const {
    return tv2d (this->tv_start_);
  }
  double duration () const {
    struct timeval tvd;
    timersub (&(this->tv_end_), &(this->tv_start_), &tvd);
    return tv2d (tvd);
  }
};

class FlowHandler : public swarm::Handler {
 private:
  std::map <u_int64_t, Flow *> flow_map_;
  uint64_t size_, pkt_;

 public:
  FlowHandler () : size_(0), pkt_(0) {}
  uint64_t size () const { return this->size_; }
  uint64_t pkt () const { return this->pkt_; }
  size_t flow_count () const { return this->flow_map_.size (); }
  void recv(swarm::ev_id eid, const  swarm::Property &p) {
    u_int64_t hv = p.get_5tuple_hash();
    std::string proto = p.param("ipv4.proto")->repr();
    struct timeval tv;
    p.tv(&tv);

    auto it = this->flow_map_.find(hv);
    Flow * f = NULL;
    if (it == this->flow_map_.end()) {
      f = new Flow(proto);
      this->flow_map_.insert(std::make_pair(hv, f));
    } else {
      f = it->second;
    }

    f->recv_pkt(p.org_len(), &tv);
    this->size_ += p.org_len ();
    this->pkt_ += 1;
  }
  void dump() {
    for (auto it = this->flow_map_.begin();
         it != this->flow_map_.end(); it++) {
      Flow * f = it->second;
      printf("%016lX, %s, %ld, %ld\n",
              it->first, f->proto().c_str(), f->len(), f->pkt());
    }
  }
  void summary() {
    uint64_t size = 0, pkt = 0, count = 0;
    for (auto it = this->flow_map_.begin();
         it != this->flow_map_.end(); it++) {
      Flow * f = it->second;
      size += f->len();
      pkt  += f->pkt();
      count++;
    }

    printf("%lu, %lu, %lu\n", count, size, pkt);
  }
};

void read_pcapfile(const std::string &fpath, optparse::Values &opt) {
  // ----------------------------------------------
  // setup pcap file
  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];

  pd = pcap_open_offline(fpath.c_str(), errbuf);
  if (pd == NULL) {
    printf("error: %s\n", errbuf);
    return;
  }
  int dlt = pcap_datalink(pd);


  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec();
  FlowHandler * fh = new FlowHandler();
  nd->set_handler("ipv4.packet", fh);

  // ----------------------------------------------
  // processing packets from pcap file
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  while (0 < pcap_next_ex(pd, &pkthdr, &pkt_data)) {
    nd->input(pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts, dlt);
  }

  if (opt.get("summary")) {
    printf ("%s, %lu, %lu, %lu\n", fpath.c_str (), fh->flow_count (),
            fh->size (), fh->pkt ());
  } else {
    fh->dump();
  }
  return;
}

int main(int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();
  psr.add_option("-s", "--summary").action("store_true").dest("summary");

  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();

  for (auto it = args.begin(); it != args.end(); it++) {
    read_pcapfile((*it), opt);
  }
}

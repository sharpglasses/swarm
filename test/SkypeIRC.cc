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
#include <string.h>

#include "../src/debug.h"
#include "../src/swarm.h"

class PcapData {
 private:
  u_char *pkt_data_;
  struct timeval ts_;
  int dlt_;
  size_t len_, caplen_;

 public:
  PcapData (const u_char *pkt_data, struct pcap_pkthdr *pkthdr, int dlt) {
    this->pkt_data_ = static_cast<u_char*> (malloc (pkthdr->caplen));
    ::memcpy (this->pkt_data_, pkt_data, pkthdr->caplen);
    this->len_    = static_cast <size_t> (pkthdr->len);
    this->caplen_ = static_cast <size_t> (pkthdr->caplen);
    ::memcpy (&(this->ts_), &(pkthdr->ts), sizeof (this->ts_));
    this->dlt_ = dlt;
  }
  ~PcapData () {
    free (this->pkt_data_);
  }

  u_char * pkt_data () const { return this->pkt_data_; }
  int dlt () const { return this->dlt_; }
  struct timeval * ts () { return &(this->ts_); }
  size_t len () const { return this->len_; }
  size_t caplen () const { return this->caplen_; }
};

class SkypeIRCFix : public ::testing::Test {
 public:
  swarm::NetDec *nd;
  std::deque <PcapData *> test_data;

  virtual void SetUp() {
    pcap_t *pd;
    nd = new swarm::NetDec ();
    char errbuf[PCAP_ERRBUF_SIZE];
    const std::string sample_file = "./data/SkypeIRC.cap";
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    pd = pcap_open_offline(sample_file.c_str (), errbuf);
    ASSERT_TRUE (pd != NULL);

    int dlt = pcap_datalink (pd);
    while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
      PcapData *p = new PcapData (pkt_data, pkthdr, dlt);
      test_data.push_back (p);
    }
  }

  virtual void TearDown() {
    while (!test_data.empty ()) {
      PcapData * p = test_data.front ();
      delete p;
      test_data.pop_front ();
    }
  }
};

namespace SkypeIRC {
  class Counter  : public swarm::Handler {
  private:
    int count_;
    void countup () {
      this->count_++;
    }

  public:
    Counter () : count_(0) {}
    void recv (swarm::ev_id eid, const swarm::Property &prop) {
      this->countup ();
    }
    int count () const {
      return this->count_;
    }
  };


  TEST_F (SkypeIRCFix, arp) {
    Counter *h1 = new Counter ();
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.packet", h1));

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), p->caplen (), *(p->ts ()),
                 p->dlt ());
    }

    EXPECT_EQ (10, h1->count ());
  }

  TEST_F (SkypeIRCFix, ether) {
    Counter *h1 = new Counter ();
    swarm::hdlr_id hid = nd->set_handler ("ether.packet", h1);

    ASSERT_NE (swarm::HDLR_NULL, hid);

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), p->caplen (), *(p->ts ()),
                 p->dlt ());
    }

    EXPECT_EQ (2263, h1->count ());
  }
}  // namespace SkypeIRC

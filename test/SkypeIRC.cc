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

namespace SkypeIRC {
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

  class Counter  : public swarm::Handler {
  private:
    int count_;

  protected:
    std::string tgt_;
    void countup () {
      this->count_++;
    }

  public:
    Counter () : count_(0) {}
    virtual void recv (swarm::ev_id eid, const swarm::Property &prop) {
      this->countup ();
    }
    int count () const {
      return this->count_;
    }
  };

  class CountTest {
  private:
    Counter * hdlr_;
    int count_;
    std::string ev_;
  public:
    CountTest (Counter * hdlr, std::string ev, int count) :
      hdlr_(hdlr), count_(count), ev_(ev) {}
    void install (swarm::NetDec *nd) {
      swarm::hdlr_id hid = nd->set_handler (this->ev_, this->hdlr_);
      ASSERT_NE (swarm::HDLR_NULL, hid);
    }
    void check () {
      EXPECT_EQ (this->count_, this->hdlr_->count ());
    }
  };



  TEST_F (SkypeIRCFix, arp) {
    class RepCount : public Counter {
      bool DEBUG = false;
      void recv (swarm::ev_id eid, const swarm::Property &prop) {
        std::string src_pr = prop.param ("arp.src_pr")->repr ();
        std::string dst_pr = prop.param ("arp.dst_pr")->repr ();
        std::string src_hw = prop.param ("arp.src_hw")->mac ();
        std::string dst_hw = prop.param ("arp.dst_hw")->mac ();
        std::string op = prop.param ("arp.op")->repr ();

        if (DEBUG) {
          debug (1, "src_pr = %s", src_pr.c_str ());
          debug (1, "src_hw = %s", src_hw.c_str ());
          debug (1, "dst_pr = %s", dst_pr.c_str ());
          debug (1, "dst_hw = %s", dst_hw.c_str ());
        }
        if (op == "REPLY" &&
            dst_pr == "192.168.1.1" && dst_hw == "00:16:E3:19:27:15" &&
            src_pr == "192.168.1.2" && src_hw == "00:04:76:96:7B:DA") {
          this->countup ();
        }
      }
    };

    class ReqCount : public Counter {
      bool DEBUG = false;
      void recv (swarm::ev_id eid, const swarm::Property &prop) {
        std::string src_pr = prop.param ("arp.src_pr")->ip4 ();
        std::string dst_pr = prop.param ("arp.dst_pr")->ip4 ();
        std::string src_hw = prop.param ("arp.src_hw")->mac ();
        std::string dst_hw = prop.param ("arp.dst_hw")->mac ();
        std::string op = prop.param ("arp.op")->repr ();

        if (DEBUG) {
          debug (1, "src_pr = %s", src_pr.c_str ());
          debug (1, "src_hw = %s", src_hw.c_str ());
          debug (1, "dst_pr = %s", dst_pr.c_str ());
          debug (1, "dst_hw = %s", dst_hw.c_str ());
        }
        if (op == "REQUEST" &&
            src_pr == "192.168.1.1" && src_hw == "00:16:E3:19:27:15" &&
            dst_pr == "192.168.1.2" && dst_hw == "00:00:00:00:00:00") {
          this->countup ();
        }
      }
    };

    Counter *h1 = new Counter ();
    Counter *h2 = new Counter ();
    Counter *h3 = new Counter ();
    Counter *req = new ReqCount ();
    Counter *rep = new RepCount ();

    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.packet",  h1));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.request", h2));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.reply",   h3));

    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.request", req));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.reply",   rep));

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), p->caplen (), *(p->ts ()),
                 p->dlt ());
    }

    EXPECT_EQ (10, h1->count ());
    EXPECT_EQ (5, h2->count ());
    EXPECT_EQ (5, h3->count ());
    EXPECT_EQ (5, req->count ());
    EXPECT_EQ (5, rep->count ());
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



  TEST_F (SkypeIRCFix, ipv4) {
    class SrcCount : public Counter {
    public:
      explicit SrcCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("ipv4.src")->repr () == this->tgt_) { this->countup (); }
      }
    };

    class DstCount : public Counter {
    public:
      explicit DstCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("ipv4.dst")->repr () == this->tgt_) { this->countup (); }
      }
    };

    class ProtoCount : public Counter {
    public:
      explicit ProtoCount (const std::string &proto) { this->tgt_ = proto; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("ipv4.proto")->repr () == this->tgt_) { this->countup (); }
      }
    };

    class LenCount : public Counter {
    public:
      explicit LenCount (const std::string &tgt) { this->tgt_ = tgt; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        std::string data = p.param ("ipv4.total")->repr ();
        if (data == this->tgt_) { this->countup (); }
      }
    };


    std::deque <CountTest *> tests_;
#define __REG_TC(HDLR, EV_NAME, COUNT) \
    tests_.push_back (new CountTest ((HDLR), EV_NAME, COUNT));

    __REG_TC (new Counter (), "ipv4.packet", 2247);
    __REG_TC (new SrcCount ("212.204.214.114"), "ipv4.packet", 141);
    __REG_TC (new DstCount ("71.10.179.129"), "ipv4.packet", 43);
    __REG_TC (new SrcCount ("212.204.214.114"), "ipv4.packet", 141);
    __REG_TC (new ProtoCount ("TCP"), "ipv4.packet", 1150);
    __REG_TC (new ProtoCount ("UDP"), "ipv4.packet", 1072);
    __REG_TC (new LenCount ("79"), "ipv4.packet", 28);
#undef __REG_TC

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->install (nd);
    }

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), p->caplen (), *(p->ts ()),
                 p->dlt ());
    }

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->check ();
    }
  }


  TEST_F (SkypeIRCFix, udp) {
    class SrcCount : public Counter {
    public:
      explicit SrcCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("udp.src_port")->repr () == this->tgt_) {
          this->countup ();
        }
      }
    };

    class DstCount : public Counter {
    public:
      explicit DstCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("udp.dst_port")->repr () == this->tgt_) {
          this->countup ();
        }
      }
    };

    class LenCount : public Counter {
    public:
      explicit LenCount (const std::string &proto) { this->tgt_ = proto; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.param ("udp.len")->repr () == this->tgt_) {
          this->countup ();
        }
      }
    };



    std::deque <CountTest *> tests_;
#define __REG_TC(HDLR, EV_NAME, COUNT) \
    tests_.push_back (new CountTest ((HDLR), EV_NAME, COUNT));

    __REG_TC (new Counter (), "udp.packet", 1072);
    __REG_TC (new SrcCount ("53"), "udp.packet", 353);
    __REG_TC (new DstCount ("53"), "udp.packet", 354);
    __REG_TC (new LenCount ("38"), "udp.packet", 29);
#undef  __REG_TC

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->install (nd);
    }

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), p->caplen (), *(p->ts ()),
                 p->dlt ());
    }

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->check ();
    }
  }

}  // namespace SkypeIRC

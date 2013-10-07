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

#include <pcap.h>
#include <swarm.h>
#include "./optparse.h"

class NetDecBench : public swarm::Task {
 private:
  swarm::NetDec *nd_;
  uint64_t prev_len_;
  uint64_t prev_pkt_;
  double prev_ts_;

 public:
  explicit NetDecBench (swarm::NetDec *nd) : nd_(nd), prev_len_(0),
                                             prev_pkt_(0), prev_ts_(0) {
  }
  ~NetDecBench () {
  }
  void exec (const struct timespec &ts) {
    this->stat ();
  }
  void stat () {
    if (this->prev_ts_ == 0) {
      // this->prev_ts_ = this->nd_->init_ts ();
    }

    /*
    double now_ts = nd->now_ts ();
    double delta = now_ts - this->prev_ts_;

    uint64_t curr_len = this->nd_->recv_len ();
    uint64_t curr_pkt = this->nd_->recv_pkt ();

    printf ("%16.6f %7.3 Mbps, %7.3 Kpps\n", delta,
            static_cast<double>(curr_len) / delta / 1000000,
            static_cast<double>(curr_pkt) / delta / 1000);

    this->prev_ts_ = now_ts;
    */
  }
};

bool do_benchmark (const optparse::Values& opt) {
  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  NetDecBench *nd_bench = new NetDecBench (nd);

  // ----------------------------------------------
  // processing packets from pcap file
  swarm::NetCap *nc = new swarm::NetCap (nd);

  if (!(opt.is_set ("read_file") ^ opt.is_set ("interface"))) {
    fprintf (stderr, "error: can't specify read_file option "
             "and interface option\n");
    return false;
  }

  if (opt.is_set ("read_file")) {
    if (!nc->add_pcapfile (opt["read_file"])) {
      fprintf (stderr, "add_pcapfile error: %s\n", nc->errmsg ().c_str ());
      return false;
    }

    nc->set_repeat_timer (nd_bench, 1000);
  } else if (opt.is_set ("interface")) {
    if (!nc->add_device (opt["interface"])) {
      fprintf (stderr, "add_interface error: %s\n", nc->errmsg ().c_str ());
      return false;
    }
  }

  if (!nc->start ()) {
    fprintf (stderr, "error: %s\n", nc->errmsg ().c_str ());
  }

  nd_bench->stat ();
  return true;
}

int main (int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();

  psr.add_option("-r").dest("read_file")
    .help("Specify read pcap format file(s)");
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");

  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();

  do_benchmark (opt);

  return 0;
}

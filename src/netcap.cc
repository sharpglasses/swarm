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
#include <assert.h>
#include <string>

#include "./netcap.h"
#include "./netdec.h"
#include "./debug.h"

namespace swarm {
  bool NetCap::set_pcap_filter (pcap_t *pd, const std::string &filter,
                                       std::string *errmsg) {
    if (!filter.empty ()) {
      struct bpf_program fp;
      bpf_u_int32 net  = 0;
      bpf_u_int32 mask = 0;

      /*
      if (pcap_lookupnet(dev.c_str (), &net, &mask, errbuf) == -1) {
        net = 0;
      }
      */

      if (pcap_compile (pd, &fp, filter.c_str (), net, mask) < 0 ||
          pcap_setfilter (pd, &fp) == -1) {
        *errmsg  = "filter compile/set error: ";
        *errmsg += pcap_geterr (pd);
        *errmsg += " \"" + filter + "\"";
        return false;
      }
    }

    return true;
  }

  NetCap::NetCap (NetDec *nd) : nd_(nd), pcap_(NULL), dlt_(-1) {
  }
  NetCap::~NetCap () {
  }
  void NetCap::set_netdec (NetDec *nd) {
    this->nd_ = nd;
  }

  bool NetCap::add_device (const std::string &dev,
                           const std::string &filter) {
    pcap_t * pd = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open interface
    if (NULL == (pd = pcap_open_live (dev.c_str (), PCAP_BUFSIZE_,
                                      1, PCAP_TIMEOUT_, errbuf))) {
      this->errmsg_.assign (errbuf);
      return false;
    }

    // set filter
    if (!NetCap::set_pcap_filter (pd, filter, &(this->errmsg_))) {
      return false;
    }

    // delegate pcap descriptor
    this->pcap_ = pd;
    this->dlt_ = pcap_datalink (pd);
    return true;
  }

  bool NetCap::add_pcapfile (const std::string &fpath,
                             const std::string &filter) {
    // ----------------------------------------------
    // setup pcap file
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];

    pd = ::pcap_open_offline(fpath.c_str (), errbuf);
    if (pd == NULL) {
      this->errmsg_.assign (errbuf);
      return false;
    }

    // set filter
    if (!NetCap::set_pcap_filter (pd, filter, &(this->errmsg_))) {
      return false;
    }

    // delegate pcap descriptor
    this->pcap_ = pd;
    this->dlt_ = pcap_datalink (pd);
    assert (this->nd_);
    return true;
  }

  inline void timerinc (struct timeval *tv, struct timeval *delta) {
    static const time_t ONESEC = 1000 * 1000;  // in micro-second
    tv->tv_sec  += delta->tv_sec;
    tv->tv_usec += delta->tv_usec;
    if (tv->tv_usec > ONESEC) {
      tv->tv_sec += 1;
      tv->tv_usec -= ONESEC;
    }
  }

  void NetCap::timer (void *obj) {
  }

  bool NetCap::start () {
    // ----------------------------------------------
    // processing packets from pcap file
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    struct timeval prev_rts, prev_pts, curr_rts, delta_pts, delta_rts;
    struct timeval timeout_rts;
    struct timeval timeout_pts;
    int rc;

    timeout_rts.tv_sec = 0;
    timeout_rts.tv_usec = 100 * 1000;
    timeout_pts.tv_sec = 0;
    timeout_pts.tv_usec = 100 * 1000;

    ::memset (&prev_pts, 0, sizeof (prev_pts));
    ::gettimeofday (&prev_rts, NULL);
    while (true) {
      rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data);

      if (rc == 1) {
        this->nd_->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts,
                          this->dlt_);
      } else {
        if (rc == -2) {
          break;
        } else if (rc < 0) {
          rc = false;
          this->errmsg_ = pcap_geterr (this->pcap_);
          break;
        }
      }

#define TIMER_ENABLE
#ifdef TIMER_ENABLE
      // ::gettimeofday (&curr_rts, NULL);
      timersub (&curr_rts, &prev_rts, &delta_rts);
      timersub (&pkthdr->ts, &prev_pts, &delta_pts);

      if (timercmp (&timeout_rts, &delta_rts, <)) {
        // fire per 10ms
        debug (0, "fire by real-timestamp");
        timerinc (&prev_rts, &timeout_rts);
      }

      if (timercmp (&timeout_pts, &delta_pts, <)) {
        // fire per 100ms
        debug (0, "fire by packet-timestamp");
        timerinc (&prev_pts, &timeout_pts);
        if (timercmp (&prev_pts, &pkthdr->ts, <)) {
          ::memcpy (&prev_pts, &pkthdr->ts, sizeof (prev_pts));
        }
      }
#endif  // TIMER_ENABLE
    }

    pcap_close (this->pcap_);
    this->pcap_ = NULL;
    return rc;
  }

  bool NetCap::capture (const std::string &dev, const std::string &filter) {
    pcap_t * pd = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open interface
    if (NULL == (pd = pcap_open_live (dev.c_str (), PCAP_BUFSIZE_,
                                      1, PCAP_TIMEOUT_, errbuf))) {
      this->errmsg_.assign (errbuf);
      return false;
    }

    // set filter
    if (!NetCap::set_pcap_filter (pd, filter, &(this->errmsg_))) {
      return false;
    }

    // delegate pcap descriptor
    this->pcap_ = pd;
    this->dlt_ = pcap_datalink (pd);

    // ----------------------------------------------
    // processing packets from pcap file
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    int rc;
    bool res = true;

    while (true) {
      rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data);

      if (rc == 1) {
        this->nd_->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts,
                          this->dlt_);
      } else {
        if (rc == -2) {
          break;
        } else if (rc < 0) {
          rc = false;
          this->errmsg_ = pcap_geterr (this->pcap_);
          break;
        }
      }
    }

    pcap_close (this->pcap_);
    this->pcap_ = NULL;
    return rc;
  }
  bool NetCap::capture_alldev (const std::string &filter) {
    assert (0);  // this function is not supported still this version
    return false;
  }
  bool NetCap::read_pcapfile (const std::string &fpath,
                               const std::string &filter) {
    // ----------------------------------------------
    // setup pcap file
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];

    pd = ::pcap_open_offline(fpath.c_str (), errbuf);
    if (pd == NULL) {
      this->errmsg_.assign (errbuf);
      return false;
    }

    // set filter
    if (!NetCap::set_pcap_filter (pd, filter, &(this->errmsg_))) {
      return false;
    }

    // delegate pcap descriptor
    this->pcap_ = pd;
    this->dlt_ = pcap_datalink (pd);
    assert (this->nd_);

    // ----------------------------------------------
    // processing packets from pcap file
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    int rc;
    bool res = true;
    while (0 < (rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data))) {
      this->nd_->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts,
                        this->dlt_);
    }

    if (rc == -1) {
      this->errmsg_ = pcap_geterr (this->pcap_);
      res = false;
    }

    ::pcap_close (this->pcap_);
    this->pcap_ = NULL;
    return res;
  }
  const std::string &NetCap::errmsg () const {
    return this->errmsg_;
  }
}  // namespace swarm

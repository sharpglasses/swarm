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

#include <sys/time.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <assert.h>
#include <string>

#include "./netcap.h"
#include "./netdec.h"
#include "./debug.h"
#include "./timer.h"


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

  NetCap::NetCap (NetDec *nd) :
    nd_(nd),
    pcap_(NULL),
    dlt_set_(false),
    dlt_(-1),
    timer_(new RealtimeTimer ()) {
  }
  NetCap::~NetCap () {
    delete this->timer_;
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

    int dlt = pcap_datalink (pd);
    if (!this->dlt_set_ || this->dlt_ == dlt) {
      this->dlt_ = dlt;
      this->dlt_set_ = true;
    } else {
      this->errmsg_ = "DLT should be same among multiple interface";
      return false;
    }

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

    int dlt = pcap_datalink (pd);
    if (!this->dlt_set_ || this->dlt_ == dlt) {
      this->dlt_ = dlt;
      this->dlt_set_ = true;
    } else {
      this->errmsg_ = "DLT should be same among multiple pcap";
      return false;
    }

    assert (this->nd_);
    return true;
  }

  bool NetCap::start () {
    // ----------------------------------------------
    // processing packets from pcap file
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    int rc;

    std::string dec = "";
    switch (this->dlt_) {
    case DLT_EN10MB: dec = "ether"; break;
    case DLT_RAW:    dec = "ipv4";  break;
    default:
      this->errmsg_ =
        "Only DLT_EN10MB and DLT_RAW are supported in this version";
      return false;
    }

    while (true) {
      rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data);

      if (rc == 1) {
        this->nd_->input (pkt_data, pkthdr->len, pkthdr->ts, pkthdr->caplen);
      } else {
        if (rc == -2) {
          break;
        } else if (rc < 0) {
          rc = false;
          this->errmsg_ = pcap_geterr (this->pcap_);
          break;
        }
      }

      if (this->timer_->ready ()) {
        this->timer_->fire ();
      }
    }

    this->timer_->stop ();

    pcap_close (this->pcap_);
    this->pcap_ = NULL;
    return rc;
  }


  task_id NetCap::set_onetime_timer (Task *task, int delay_msec) {
    return this->timer_->install_task (task, Timer::ONCE, delay_msec);
  }
  task_id NetCap::set_repeat_timer (Task *task, int interval_msec) {
    return this->timer_->install_task (task, Timer::REPEAT, interval_msec);
  }
  bool NetCap::unset_timer (task_id id) {
    return this->timer_->remove_task (id);
  }

  const std::string &NetCap::errmsg () const {
    return this->errmsg_;
  }
}  // namespace swarm

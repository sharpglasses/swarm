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
  // -------------------------------------------------------------------
  // class NetCap
  //
  NetCap::NetCap () :
    nd_(NULL),
    timer_(new RealtimeTimer ()) {
  }
  NetCap::~NetCap () {
    delete this->timer_;
  }
  void NetCap::bind_netdec (NetDec *nd) {
    this->nd_ = nd;
  }


  bool NetCap::start () {
    this->timer_->start ();
    bool rc = this->run ();
    this->timer_->stop ();
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

  void NetCap::set_status(Status st) {
    this->status_ = st;
  }
  void NetCap::set_errmsg (const std::string &errmsg) {
    this->errmsg_ = errmsg;
  }
  const std::string &NetCap::errmsg () const {
    return this->errmsg_;
  }


  // -------------------------------------------------------------------
  // class PcapBase
  //
  PcapBase::PcapBase () : pcap_(NULL) {
  }
  PcapBase::~PcapBase () {
  }
  bool PcapBase::set_filter (const std::string &filter) {
    if (this->pcap_ == NULL) {
      this->set_errmsg("Can't apply filter to unavailable device/file");
      return false;
    }

    if (!filter.empty ()) {
      struct bpf_program fp;
      bpf_u_int32 net  = 0;
      bpf_u_int32 mask = 0;

      /*
      if (pcap_lookupnet(dev.c_str (), &net, &mask, errbuf) == -1) {
        net = 0;
      }
      */

      if (pcap_compile (this->pcap_, &fp, filter.c_str (), net, mask) < 0 ||
          pcap_setfilter (this->pcap_, &fp) == -1) {
        std::string err;
        err = "filter compile/set error: ";
        err += pcap_geterr (this->pcap_);
        err += " \"" + filter + "\"";
        this->set_errmsg (err);
        return false;
      }

      this->filter_ = filter;
    }

    return true;
  }

  bool PcapBase::run () {
    // delegate pcap descriptor
    int dlt = pcap_datalink (this->pcap_);
    std::string dec = "";
    switch (dlt) {
    case DLT_EN10MB: dec = "ether"; break;
    case DLT_RAW:    dec = "ipv4";  break;
    case DLT_LINUX_SLL: dec = "lcc"; break;
    default:
      this->set_errmsg ("Only DLT_EN10MB and DLT_RAW are "
                        "supported in this version");
      this->set_status (NetCap::FAIL);
      return false;
    }

    std::string err;
    if (!this->netdec()->set_default_decoder(dec)) {
      this->set_errmsg(this->netdec()->errmsg());
      this->set_status(FAIL);
      return false;
    }

    // ----------------------------------------------
    // processing packets from pcap file
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    int rc;

    while (true) {
      rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data);

      if (rc == 1) {
        this->netdec()->input (pkt_data, pkthdr->len, pkthdr->ts,
                               pkthdr->caplen);
      } else {
        if (rc == -2) {
          break;
        } else if (rc < 0) {
          rc = false;
          this->set_errmsg (pcap_geterr (this->pcap_));
          break;
        }
      }

      this->timer_proc ();
    }

    pcap_close (this->pcap_);
    this->pcap_ = NULL;
    return rc;
  }



  // -------------------------------------------------------------------
  // class CapPcapDev
  //
  CapPcapDev::CapPcapDev (const std::string &dev_name) :
    dev_name_(dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    this->pcap_ = pcap_open_live (this->dev_name_.c_str (), PCAP_BUFSIZE_,
                                  1, PCAP_TIMEOUT_, errbuf);
    // open interface
    if (NULL == this->pcap_) {
      this->set_errmsg (errbuf);
      this->set_status (NetCap::FAIL);
    } else {
      this->set_status (NetCap::READY);
    }
  }
  CapPcapDev::~CapPcapDev () {
  }



  // -------------------------------------------------------------------
  // class CapPcapFile
  //
  CapPcapFile::CapPcapFile (const std::string &file_path) :
    file_path_(file_path) {
    char errbuf[PCAP_ERRBUF_SIZE];

    this->pcap_ = ::pcap_open_offline(this->file_path_.c_str (), errbuf);
    if (this->pcap_ == NULL) {
      this->set_errmsg (errbuf);
      this->set_status (NetCap::FAIL);
    } else {
      this->set_status (NetCap::READY);
    }
  }
  CapPcapFile::~CapPcapFile () {
  }
}  // namespace swarm

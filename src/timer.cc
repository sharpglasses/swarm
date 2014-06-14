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

#include <assert.h>
#include <sys/time.h>
#include <math.h>

#include "./timer.h"
#include "./debug.h"

namespace swarm {
  Task::Task () {
  }
  Task::~Task () {
  }
  
  TaskEntry::TaskEntry (task_id id, Task *task, float interval,
                        struct ev_loop *loop) :
    id_(id), task_(task), interval_(interval), loop_(loop) {
    ev_timer_init(&(this->timer_), TaskEntry::work, 0.0, this->interval_);
    ev_timer_start(this->loop_, &(this->timer_));
  }
  TaskEntry::~TaskEntry () {
    ev_timer_stop(this->loop_, &(this->timer_));    
  }
  void TaskEntry::work(EV_P_ struct ev_timer *w, int reeeevents) {
    TaskEntry *ent = reinterpret_cast<TaskEntry*>(w->data);
    double tv = ev_now(EV_A);
    double tv_sec, tv_nsec;
    struct timespec ts;
    tv_nsec = modf(tv, &tv_sec);
    ts.tv_sec  = static_cast<time_t>(tv_sec);
    ts.tv_nsec = static_cast<long>(tv_nsec * 1e+9);
    ent->task_->exec(ts);
  };

}  // namespace swarm


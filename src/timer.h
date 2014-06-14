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

#ifndef SRC_TIMER_H__
#define SRC_TIMER_H__

#include <stdint.h>
#include <map>
#include <ev.h>
#include "./common.h"

namespace swarm {
  typedef uint64_t tick_t;
  class TaskEntry;
  class Task;

  // ----------------------------------------------------------
  // Task
  class Task {
  protected:
    void stop();
    void exit();

  public:
    Task ();
    virtual ~Task ();
    virtual void exec (const struct timespec &tv) = 0;
  };

  // ----------------------------------------------------------
  // TaskEntry
  class TaskEntry {
  private:
    task_id id_;
    Task *task_;
    float interval_;
    struct ev_loop *loop_;
    struct ev_timer timer_;

  public:
    TaskEntry (task_id id, Task *task, float interval, struct ev_loop *loop);
    ~TaskEntry ();
    task_id id () const { return this->id_; }
    float interval () const { return this->interval_; }
    Task *task () const { return this->task_; }
    static void work (EV_P_ struct ev_timer *w, int revents);
  };


}  // namespace swarm

#endif  // SRC_TIMER_H__

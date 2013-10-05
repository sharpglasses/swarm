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

#include <pthread.h>
#include <map>
#include "./common.h"

namespace swarm {
  typedef uint64_t tick_t;
  class TaskEntry;
  class Task;

  // ----------------------------------------------------------
  // Timer
  class Timer {
  public:
    enum Mode {
      REPEAT = 1,
      ONCE,
    };

  private:
    std::multimap<tick_t, TaskEntry*> schedule_;
    std::map<task_id, TaskEntry*> task_map_;
    task_id task_id_seq_;
    tick_t curr_tick_;
    tick_t base_tick_;
    inline static tick_t msec2tick (int msec) {
      return static_cast<tick_t>(msec);
    }
    inline static tick_t timespec2tick (const struct timespec &now);
    void push_task(TaskEntry *ent);

  public:
    Timer ();
    ~Timer ();

    // Common
    task_id install_task (Task *task, Mode mode, int msec);
    bool remove_task (task_id t_id);
    void ticktock (const struct timespec &now);
  };

  // ----------------------------------------------------------
  // RealtimeTimer
  class RealtimeTimer : public Timer {
  private:
    u_int32_t ready_;
    u_int32_t enable_;
    pthread_t clock_th_;

  public:
    // Functions for REALTIME_CLOCK
    static void *clock (void *obj);
    void start ();
    void stop ();
    bool ready () const;
    void fire (); 
  };

  class WindingTimer : public Timer {
  public:
    // Functions for MANUAL_CLOCK
    
  };

  // ----------------------------------------------------------
  // Task
  class Task {
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
    tick_t interval_;
    tick_t base_;
    tick_t next_tick_;
    Timer::Mode mode_;

  public:
    TaskEntry (task_id id, Task *task, tick_t interval, tick_t base,
               Timer::Mode mode);
    ~TaskEntry ();
    task_id id () const;
    tick_t interval () const; 
    Task *task () const;    
    Timer::Mode mode () const;
    tick_t calc_next_tick (tick_t curr);
    tick_t next_tick () const;
  };


}  // namespace swarm

#endif  // SRC_TIMER_H__

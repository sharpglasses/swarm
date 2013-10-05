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
#include <pthread.h>
#include "./timer.h"
#include "./debug.h"

namespace swarm {
  Task::Task () {
  }
  Task::~Task () {
  }


  TaskEntry::TaskEntry (task_id id, Task *task, tick_t interval, tick_t base,
                        Timer::Mode mode) : 
    id_(id), task_(task), interval_(interval), base_(base), next_tick_(0),
    mode_(mode) {
  }
  TaskEntry::~TaskEntry () {
  }
  task_id TaskEntry::id () const {
    return this->id_;
  }
  tick_t TaskEntry::interval () const {
    return this->interval_;
  }
  Task *TaskEntry::task () const {
    return this->task_;
  }
  tick_t TaskEntry::calc_next_tick (tick_t curr) {
    while (this->next_tick_ <= curr) {
      assert (this->next_tick_ < this->next_tick_ + this->interval_);
      this->next_tick_ += this->interval_;
    }
    return this->next_tick_;
  }
  tick_t TaskEntry::next_tick () const {
    return this->next_tick_;
  }
  Timer::Mode TaskEntry::mode () const { 
    return this->mode_;
  }
  

#ifdef __MACH__
  static const int CLOCK_PROCESS_CPUTIME_ID = 2;
  //clock_gettime is not implemented on OSX
  int clock_gettime (int clk_id, struct timespec *t) {
    struct timeval now;
    ::gettimeofday(&now, NULL);
    t->tv_sec  = now.tv_sec;
    t->tv_nsec = now.tv_usec * 1000;
    return 0;
  }
#endif

  inline void ts_inc (struct timespec *tv, struct timespec *delta) {
    static const time_t ONESEC = (+1.0E+9);
    tv->tv_sec  += delta->tv_sec;
    tv->tv_nsec += delta->tv_nsec;
    if (tv->tv_nsec > ONESEC) {
      tv->tv_sec += 1;
      tv->tv_nsec -= ONESEC;
    }
  }

  inline void ts_add (struct timespec *tv, struct timespec *delta,
                      struct timespec *res) {
    static const time_t ONESEC = (+1.0E+9);
    res->tv_sec  = tv->tv_sec  + delta->tv_sec;
    res->tv_nsec = tv->tv_nsec + delta->tv_nsec;
    if (res->tv_nsec > ONESEC) {
      res->tv_sec += 1;
      res->tv_nsec -= ONESEC;
    }
  }

  inline void ts_sub (struct timespec *tv, struct timespec *delta,
                      struct timespec *res) {
    static const time_t ONESEC = (+1.0E+9);
    if (tv->tv_nsec >= delta->tv_nsec) {
      res->tv_sec  = tv->tv_sec  - delta->tv_sec;
      res->tv_nsec = tv->tv_nsec - delta->tv_nsec;
    } else {
      res->tv_sec  = tv->tv_sec  - delta->tv_sec - 1;
      res->tv_nsec = ONESEC + tv->tv_nsec - delta->tv_nsec;
    }
  }

  // check ts1 > ts2
  inline bool ts_gt (struct timespec *ts1, struct timespec *ts2) {
    if (ts1->tv_sec == ts2->tv_sec) {
      return (ts1->tv_nsec > ts2->tv_nsec);
    } else {
      return (ts1->tv_sec > ts2->tv_sec);
    }
  }

  Timer::Timer () : curr_tick_(0), base_tick_(0) {
  }

  Timer::~Timer () {
  }

  void Timer::push_task(TaskEntry *ent) {
    tick_t next_tick = ent->calc_next_tick (this->curr_tick_);
    this->task_map_.insert (std::make_pair (ent->id (), ent));
    this->schedule_.insert (std::make_pair (next_tick, ent));
  }

  task_id Timer::install_task (Task *task, Mode mode, int msec) {
    task_id t_id = ++(this->task_id_seq_);
    TaskEntry * ent = new TaskEntry (t_id, task, msec2tick (msec),
                                     this->curr_tick_,  mode);
    this->push_task (ent);
    return ent->id ();
  }
  bool Timer::remove_task (task_id t_id) {
    auto it = this->task_map_.find (t_id);
    if (it != this->task_map_.end ()) {
      TaskEntry *ent = it->second;
      this->task_map_.erase (it);
      for (auto s_it = this->schedule_.find (ent->next_tick ());
           s_it != this->schedule_.end (); s_it++) {
        if ((s_it->second)->next_tick () != ent->next_tick ()) {
          break;
        }
        if ((s_it->second)->id () == ent->id ()) {
          this->schedule_.erase (s_it);
          break;
        }
      }

      return true;
    } else {
      return false;
    }
  }

  tick_t Timer::timespec2tick (const struct timespec &now) {
    return now.tv_sec * 1000 + now.tv_nsec / (1000 * 1000);
  }

  void Timer::ticktock (const struct timespec &now) {
    tick_t curr = timespec2tick (now);
    if (this->base_tick_ == 0) {  // base tick is not set
      this->base_tick_ = curr;
    }
    assert (curr >= this->base_tick_);
    this->curr_tick_ = curr - this->base_tick_;

    auto begin = this->schedule_.begin ();
    auto end = this->schedule_.upper_bound (this->curr_tick_);
    for (auto it = this->schedule_.begin (); it != end; it++) {
      TaskEntry *ent = (it->second);
      Task *task = (it->second)->task();
      assert (task);
      task->exec (now);
      
      if (Timer::REPEAT == ent->mode ()) {
        this->push_task (ent);
      }
    }

    if (begin != end) {
      this->schedule_.erase (begin, end);
    }
  }

  // Functions for realtime clock
  void RealtimeTimer::start () {
    debug (1, "start timer");
    this->ready_ = 0;
    this->enable_ = 1;
    ::pthread_create (&this->clock_th_, NULL, RealtimeTimer::clock, this);
  }
  void RealtimeTimer::stop () {
    debug (1, "exiting..");
    this->enable_ = 0;
    pthread_join (this->clock_th_, NULL);
    debug (1, "exit");
  }
  bool RealtimeTimer::ready () const {
    return this->ready_;
  }
  void RealtimeTimer::fire () {
    this->ready_ = 0;
    struct timespec now;
    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &now);
    this->ticktock (now);
  }
  void *RealtimeTimer::clock (void *obj) {
    RealtimeTimer *t = static_cast<RealtimeTimer*>(obj);
    struct timespec req, rem;
    struct timespec curr_ts, next_ts, delta_ts;

    delta_ts.tv_sec = 0;
    delta_ts.tv_nsec = 100 * 1000 * 1000;

    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &next_ts);

    while (t->enable_) {
      do {
        clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &curr_ts);
        ts_inc (&next_ts, &delta_ts);
      } while (ts_gt (&curr_ts, &next_ts));

      ts_sub (&next_ts, &curr_ts, &req);
      ::nanosleep (&req, &rem);
      t->ready_ = 1;
    }

    debug (1, "exit");
    return NULL;
  }

  
}  // namespace swarm


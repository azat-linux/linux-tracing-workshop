#!/usr/bin/env python

# Based on https://github.com/goldshtn/linux-tracing-workshop
# Based on https://gist.github.com/SaveTheRbtz/807be09f73d13b80e429d45bd1707e00

"""
The MIT License (MIT)

Copyright (c) 2017 Sasha Goldshtein
Copyright (c) 2018 Alexey Ivanov

Changelog:
- Convert to python3 (Azat Khuzhin 2024-01)
- Look for pthread in libc (Azat Khuzhin 2024-01)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""



import argparse
import itertools
import sys
from time import sleep, strftime

# import: bcc comes from the dpkg_lib called bcc_libs
from bcc import BPF

# language=C
text = """
#include <linux/ptrace.h>
struct thread_mutex_key_t {
    u32 tid;
    u64 mtx;
    int lock_stack_id;
};
struct thread_mutex_val_t {
    u64 wait_time_ns;
    u64 max_wait_time_ns;
    u64 lock_time_ns;
    u64 max_lock_time_ns;
    u64 enter_count;
};
struct mutex_timestamp_t {
    u64 mtx;
    u64 timestamp;
};
struct mutex_lock_time_key_t {
    u32 tid;
    u64 mtx;
};
struct mutex_lock_time_val_t {
    u64 timestamp;
    int stack_id;
};

// Mutex to the stack id which initialized that mutex
BPF_HASH(init_stacks, u64, int);
// Main info database about mutex and thread pairs
BPF_HASH(locks, struct thread_mutex_key_t, struct thread_mutex_val_t);
// Pid to the mutex address and timestamp of when the wait started
BPF_HASH(lock_start, u32, struct mutex_timestamp_t);
// Pid and mutex address to the timestamp of when the wait ended (mutex acquired) and the stack id
BPF_HASH(lock_end, struct mutex_lock_time_key_t, struct mutex_lock_time_val_t);
// Histogram of wait times
BPF_HISTOGRAM(mutex_wait_hist, u64);
// Histogram of hold times
BPF_HISTOGRAM(mutex_lock_hist, u64);
BPF_STACK_TRACE(stacks, 65535);

int probe_mutex_lock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_timestamp_t val = {};
    val.mtx = PT_REGS_PARM1(ctx);
    val.timestamp = now;
    lock_start.update(&pid, &val);
    return 0;
}
int probe_mutex_lock_return(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_timestamp_t *entry = lock_start.lookup(&pid);
    if (entry == 0)
        return 0;   // Missed the entry
    u64 wait_time = now - entry->timestamp;
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    // If pthread_mutex_lock() returned 0, we have the lock
    if (PT_REGS_RC(ctx) == 0) {
        // Record the lock acquisition timestamp so that we can read it when unlocking
        struct mutex_lock_time_key_t key = {};
        key.mtx = entry->mtx;
        key.tid = pid;
        struct mutex_lock_time_val_t val = {};
        val.timestamp = now;
        val.stack_id = stack_id;
        lock_end.update(&key, &val);
    }
    // Record the wait time for this mutex-tid-stack combination even if locking failed
    struct thread_mutex_key_t tm_key = {};
    tm_key.mtx = entry->mtx;
    tm_key.tid = pid;
    tm_key.lock_stack_id = stack_id;
    struct thread_mutex_val_t *existing_tm_val, new_tm_val = {};
    existing_tm_val = locks.lookup_or_init(&tm_key, &new_tm_val);
    if (existing_tm_val->max_wait_time_ns < wait_time) {
        existing_tm_val->max_wait_time_ns = wait_time;
    }
    existing_tm_val->wait_time_ns += wait_time;
    if (PT_REGS_RC(ctx) == 0) {
        existing_tm_val->enter_count += 1;
    }
    u64 mtx_slot = bpf_log2l(wait_time / 1000);
    mutex_wait_hist.increment(mtx_slot);
    lock_start.delete(&pid);
    return 0;
}
int probe_mutex_unlock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 mtx = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_lock_time_key_t lock_key = {};
    lock_key.mtx = mtx;
    lock_key.tid = pid;
    struct mutex_lock_time_val_t *lock_val = lock_end.lookup(&lock_key);
    if (lock_val == 0)
        return 0;   // Missed the lock of this mutex
    u64 hold_time = now - lock_val->timestamp;
    struct thread_mutex_key_t tm_key = {};
    tm_key.mtx = mtx;
    tm_key.tid = pid;
    tm_key.lock_stack_id = lock_val->stack_id;
    struct thread_mutex_val_t *existing_tm_val = locks.lookup(&tm_key);
    if (existing_tm_val == 0)
        return 0;   // Couldn't find this record

    if (existing_tm_val->max_lock_time_ns < hold_time) {
        existing_tm_val->max_lock_time_ns = hold_time;
    }
    existing_tm_val->lock_time_ns += hold_time;
    u64 slot = bpf_log2l(hold_time / 1000);
    mutex_lock_hist.increment(slot);
    lock_end.delete(&lock_key);
    return 0;
}
int probe_mutex_init(struct pt_regs *ctx)
{
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    u64 mutex_addr = PT_REGS_PARM1(ctx);
    init_stacks.update(&mutex_addr, &stack_id);
    return 0;
}
"""


def attach(bpf, pid):
    lib = "/lib/libc.so.6"
    bpf.attach_uprobe(name=lib, sym="pthread_mutex_init", fn_name="probe_mutex_init", pid=pid)
    bpf.attach_uprobe(name=lib, sym="pthread_mutex_lock", fn_name="probe_mutex_lock", pid=pid)
    bpf.attach_uretprobe(name=lib, sym="pthread_mutex_lock", fn_name="probe_mutex_lock_return", pid=pid)
    bpf.attach_uprobe(name=lib, sym="pthread_mutex_unlock", fn_name="probe_mutex_unlock", pid=pid)


def format_stack(bpf, pid, stacks, stack_id):
    formatted = []
    for addr in stacks.walk(stack_id):
        formatted.append(
            "\t\t{:16s} ({:x})".format(bpf.sym(
                addr, pid, show_module=True, show_offset=True).decode(), addr)
        )
    return "\n".join(formatted)


parser = argparse.ArgumentParser(
    description=(
        "Profile lock contention"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int,
                    help="pid of the process to profile", required=True)

parser.add_argument("interval", nargs="?", default=99999999, type=int,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999, type=int,
                    help="number of outputs")
parser.add_argument("-I", "--show-mutex-init", action="store_true",
                    help="print all mutex creations")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("--min-avg-wait-time-us", default=0, type=int,
                    help="do not print locks with average wait time less than given number of us")
parser.add_argument("--min-avg-hold-time-us", default=0, type=int,
                    help="do not print locks with average hold time less than given number of us")
parser.add_argument("--min-total-wait-time-us", default=0, type=int,
                    help="do not print locks with total wait time less than given number of us")
parser.add_argument("--min-total-hold-time-us", default=0, type=int,
                    help="do not print locks with total hold time less than given number of us")
parser.add_argument("--min-max-wait-time-us", default=0, type=int,
                    help="do not print locks with max wait time less than given number of us")
parser.add_argument("--min-max-hold-time-us", default=0, type=int,
                    help="do not print locks with max hold time less than given number of us")
parser.add_argument("--min-enter-count", default=0, type=int,
                    help="do not print locks with less than given number of hits")

args = parser.parse_args()

bpf = BPF(text=text)
attach(bpf, args.pid)
init_stacks = bpf["init_stacks"]
stacks = bpf["stacks"]
locks = bpf["locks"]
mutex_lock_hist = bpf["mutex_lock_hist"]
mutex_wait_hist = bpf["mutex_wait_hist"]

countdown = args.count
exiting = 0
while True:
    if args.timestamp:
        print("{:<8s}\n".format(strftime(b"%H:%M:%S")))

    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    mutex_ids = {}
    next_mutex_id = 1

    for k, v in list(init_stacks.items()):
        mutex_id = "#{:d}".format(next_mutex_id)
        next_mutex_id += 1
        mutex_ids[k.value] = mutex_id
        if args.show_mutex_init:
            print("init stack for mutex {:x} ({:s})".format(k.value, mutex_id))
            print(format_stack(bpf, args.pid, stacks, v.value))
            print("")

    if args.folded:
        for k, v in list(locks.items()):
            value = v.wait_time_ns
            line = [bpf.sym(addr, args.pid, show_module=True)
                    for addr in reversed(list(stacks.walk(k.lock_stack_id)))]
            if not line:
                line = ["unknown"]
            print("{:s} {:d}".format(";".join(line), value))
    else:
        grouper = lambda k_v1: k_v1[0].tid
        sorted_by_thread = sorted(list(locks.items()), key=grouper)
        locks_by_thread = itertools.groupby(sorted_by_thread, grouper)
        for tid, items in locks_by_thread:
            formatted = []
            for k, v in sorted(items, key=lambda k_v: -k_v[1].wait_time_ns):
                if v.enter_count < args.min_enter_count:
                    continue

                total_wait_time_us = v.wait_time_ns / 1000.0
                total_hold_time_us = v.lock_time_ns / 1000.0
                if total_wait_time_us < args.min_total_wait_time_us:
                    continue
                if total_hold_time_us < args.min_total_hold_time_us:
                    continue

                avg_wait_time_us = total_wait_time_us / v.enter_count
                avg_hold_time_us = total_hold_time_us / v.enter_count
                if avg_wait_time_us < args.min_avg_wait_time_us:
                    continue
                if avg_hold_time_us < args.min_avg_hold_time_us:
                    continue

                max_wait_time_us = v.max_wait_time_ns / 1000.0
                max_hold_time_us = v.max_lock_time_ns / 1000.0
                if max_wait_time_us < args.min_max_wait_time_us:
                    continue
                if max_hold_time_us < args.min_max_hold_time_us:
                    continue

                mutex_descr = mutex_ids[k.mtx] if k.mtx in mutex_ids else bpf.sym(k.mtx, args.pid)
                formatted.append(
                    "\tmutex {:s}, "
                    "total_wait_time_us {:.2f}, total_hold_time_us {:.2f}, "
                    "avg_wait_time_us {:.2f}, avg_hold_time_us {:.2f}, "
                    "max_wait_time_us {:.2f}, max_hold_time_us {:.2f}, "
                    "enter_count {:d}".format(
                        mutex_descr.decode(),
                        total_wait_time_us, total_hold_time_us,
                        avg_wait_time_us, avg_hold_time_us,
                        max_wait_time_us, max_hold_time_us,
                        v.enter_count,
                    )
                )
                formatted.append(format_stack(bpf, args.pid, stacks, k.lock_stack_id))

            if formatted:
                print("thread {:d}".format(tid))
                for s in formatted:
                    print(s)
                    print()

    if not args.folded:
        mutex_wait_hist.print_log2_hist(val_type="wait time (us)")
        print()
        mutex_lock_hist.print_log2_hist(val_type="hold time (us)")
        print("\n")

    mutex_wait_hist.clear()
    mutex_lock_hist.clear()
    stacks.clear()
    locks.clear()
    init_stacks.clear()

    countdown -= 1
    if exiting or countdown == 0:
        sys.exit()

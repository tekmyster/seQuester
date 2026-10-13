/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQ_KERNEL61_COMPAT_H
#define SQ_KERNEL61_COMPAT_H
#include <linux/version.h>

/* Explicit build qualification profile, not automatic runtime admission.
 * Linux 6.1 has no per-program kfunc filter. Only the atomic tracing subset
 * is registered below; sleepable/path/legacy capture APIs are never exposed.
 */
#ifdef SQ_KERNEL61_ATOMIC_ONLY
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,0) || LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
#error SQ_KERNEL61_ATOMIC_ONLY requires exact Linux 6.1 headers
#endif
#define __bpf_kfunc __used noinline
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
static inline struct timespec64 sq_inode_mtime_61(const struct inode *inode)
{
 return inode->i_mtime;
}
#define inode_get_mtime sq_inode_mtime_61
#endif
#endif

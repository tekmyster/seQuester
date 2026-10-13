#pragma once
struct sq_key { unsigned long long inode; unsigned int device; unsigned int padding; };
struct sq_counters { unsigned long long sequence; unsigned long long dropped; };
struct sq_event {
 unsigned long long sequence,observed_ns,process_start_ns,inode,exe_inode,cgroup_id;
 long long result;
 unsigned int pid,tid,ppid,uid,euid,fsuid,loginuid,opener_fsuid;
 unsigned int device,exe_device,operation,stage,mask,flags;
 char comm[16],exe_name[256],image[512],path[512],file_name[256];
};

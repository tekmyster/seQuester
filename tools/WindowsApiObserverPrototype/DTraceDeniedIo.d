/* Lab qualification only. Run with -q -s <script> -p <owned actor PID>.
 * No destructive actions. No kernel structure offsets or fabricated user SID.
 * Kernel syscall arguments differ from the classic ETW syscall address payload.
 * Validate probe availability and arg types on the actual OS before enabling.
 * Entry/return records need independent PID-birth and target-handle truth.
 * STATUS_PENDING is not a final asynchronous completion.
 */
BEGIN { printf("SQ_TRACE_READY\n"); }

syscall::NtReadFile:entry, syscall::NtWriteFile:entry
/ pid == SQ_TARGET_PID /
{
    self->sq_active = 1;
    self->sq_handle = arg0;
    self->sq_length = (uint32_t)arg6;
    self->sq_entry = timestamp;
    printf("SQ_IO_ENTRY pid=%d tid=%d operation=%s handle=0x%llx length=%llu monotonic=%llu wall=%llu\n",
        pid, tid, probefunc, (unsigned long long)self->sq_handle,
        (unsigned long long)self->sq_length, (unsigned long long)timestamp,
        (unsigned long long)walltimestamp);
}

syscall::NtSetInformationFile:entry
/ pid == SQ_TARGET_PID /
{
    self->sq_active = 1;
    self->sq_handle = arg0;
    self->sq_length = (uint32_t)arg3;
    self->sq_entry = timestamp;
    printf("SQ_SET_ENTRY pid=%d tid=%d operation=%s handle=0x%llx length=%llu information_class=%u monotonic=%llu wall=%llu\n",
        pid, tid, probefunc, (unsigned long long)self->sq_handle,
        (unsigned long long)self->sq_length, (uint32_t)arg4,
        (unsigned long long)timestamp, (unsigned long long)walltimestamp);
}

syscall::NtReadFile:return, syscall::NtWriteFile:return,
syscall::NtSetInformationFile:return
/ pid == SQ_TARGET_PID && self->sq_active /
{
    printf("SQ_IO_RETURN pid=%d tid=%d operation=%s handle=0x%llx status=0x%08x entry_monotonic=%llu monotonic=%llu wall=%llu\n",
        pid, tid, probefunc, (unsigned long long)self->sq_handle, (uint32_t)arg0,
        (unsigned long long)self->sq_entry, (unsigned long long)timestamp,
        (unsigned long long)walltimestamp);
    self->sq_active = 0;
    self->sq_handle = 0;
    self->sq_length = 0;
    self->sq_entry = 0;
}

/* Finite qualification, not an endpoint daemon. Collection errors must fail
 * acceptance; do not exit successfully on an ERROR probe or ignore drops. */
tick-15sec { exit(0); }
ERROR { printf("SQ_COLLECTION_ERROR\n"); exit(1); }

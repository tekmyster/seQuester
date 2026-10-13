/* Private callback-context qualification. No destructive actions or tokens. */
BEGIN { printf("SQ_TRACE_READY\n"); }
syscall::NtReadFile:entry, syscall::NtReadFile:return,
syscall::NtWriteFile:entry, syscall::NtWriteFile:return,
syscall::NtSetInformationFile:entry, syscall::NtSetInformationFile:return
/ pid == SQ_TARGET_PID /
{ }
tick-30sec { exit(0); }
ERROR { printf("SQ_COLLECTION_ERROR\n"); exit(1); }

; Owned negative fixture only. No kernel patch, executable memory allocation,
; protection change, or external process manipulation. Win64 ten-argument ABI:
; NtReadFile's nine arguments plus this validated build's service identifier.
.code
SqOwnedDirectRead PROC
    mov r10, rcx
    mov eax, DWORD PTR [rsp+80]
    syscall
    ret
SqOwnedDirectRead ENDP
END

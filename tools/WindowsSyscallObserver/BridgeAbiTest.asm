OPTION CASEMAP:NONE
EXTERN SqReadEntry:PROC
EXTERN SqWriteEntry:PROC
EXTERN SqSetEntry:PROC
.code
SqAbiExercise PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp,58h
    .allocstack 58h
    .endprolog
    mov r11d,ecx
    mov rbx,101h
    mov rbp,102h
    mov rsi,103h
    mov rdi,104h
    mov r12,105h
    mov r13,106h
    mov r14,107h
    mov r15,108h
    mov ecx,1
    mov edx,2
    mov r8d,3
    mov r9d,4
    mov qword ptr [rsp+20h],5
    mov qword ptr [rsp+28h],6
    mov qword ptr [rsp+30h],7
    mov qword ptr [rsp+38h],8
    mov qword ptr [rsp+40h],9
    cmp r11d,1
    je read_case
    cmp r11d,2
    je write_case
    call SqSetEntry
    jmp check_result
read_case:
    call SqReadEntry
    jmp check_result
write_case:
    call SqWriteEntry
check_result:
    cmp eax,0C0000022h
    jne failure
    cmp rbx,101h
    jne failure
    cmp rbp,102h
    jne failure
    cmp rsi,103h
    jne failure
    cmp rdi,104h
    jne failure
    cmp r12,105h
    jne failure
    cmp r13,106h
    jne failure
    cmp r14,107h
    jne failure
    cmp r15,108h
    jne failure
    xor eax,eax
    jmp finish
failure:
    mov eax,1
finish:
    add rsp,58h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
SqAbiExercise ENDP
END

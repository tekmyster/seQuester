; Research x64 entry/return bridge. No nonvolatile registers are modified here.
; C bodies preserve them by the ordinary ABI. Do not dynamically unload before
; all EPT entry redirects are disabled and root-counted returns have drained.
OPTION CASEMAP:NONE
EXTERN SqReadBody:PROC
EXTERN SqWriteBody:PROC
EXTERN SqSetBody:PROC
.code
SQ_BRIDGE MACRO entryName,bodyName,returnName,copyNine
PUBLIC entryName
PUBLIC returnName
entryName PROC FRAME
    sub rsp,68h
    .allocstack 68h
    .endprolog
    mov r10,[rsp+90h]
    mov [rsp+20h],r10
    IF copyNine
        mov r10,[rsp+98h]
        mov [rsp+28h],r10
        mov r10,[rsp+0A0h]
        mov [rsp+30h],r10
        mov r10,[rsp+0A8h]
        mov [rsp+38h],r10
        mov r10,[rsp+0B0h]
        mov [rsp+40h],r10
    ENDIF
    call bodyName
    ; RAX result and every nonvolatile register now contain the original
    ; function's returned state. The remaining code uses volatile registers.
    mov r9,rax
    mov rdx,[rsp+68h]
    lea r8,[rsp+70h]
    add rsp,68h
    mov ecx,53510001h
returnName::
IFDEF SQ_ABI_TEST
    ; User-mode ABI test only. Proves forwarding/preservation, not VM-exit.
    mov rax,r9
    ret
ELSE
    vmcall
    ; A supported root handler returns directly to the original caller. An
    ; unsupported handler injects #UD. This candidate is never load-admitted
    ; until root glue, ABI and lifetime tests pass in VMware.
    int 3
ENDIF
entryName ENDP
ENDM
SQ_BRIDGE SqReadEntry,SqReadBody,SqReadReturnVmcall,1
SQ_BRIDGE SqWriteEntry,SqWriteBody,SqWriteReturnVmcall,1
SQ_BRIDGE SqSetEntry,SqSetBody,SqSetReturnVmcall,0
END

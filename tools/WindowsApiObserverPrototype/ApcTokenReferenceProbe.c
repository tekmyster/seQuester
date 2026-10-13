// Compile-only qualification input. NOT part of the production driver.
// WDK 10.0.26100 ntifs.h annotates PsReferenceImpersonationToken <= APC_LEVEL,
// while Microsoft Learn specifies PASSIVE_LEVEL. Resolve this discrepancy and
// qualify on the admitted OS builds before use. No kernel deployment is implied.
#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)

typedef struct _SQ_APC_TOKEN_REFERENCE_PROBE {
    PACCESS_TOKEN Reference;
    BOOLEAN Impersonating, CopyOnOpen, EffectiveOnly;
    SECURITY_IMPERSONATION_LEVEL Level;
    KIRQL ReferenceIrql;
} SQ_APC_TOKEN_REFERENCE_PROBE;

_IRQL_requires_(APC_LEVEL)
NTSTATUS SqProbeReferenceAtApc(_In_ PETHREAD actualThread,
                              _Out_ SQ_APC_TOKEN_REFERENCE_PROBE* result)
{
    if(!actualThread||!result||KeGetCurrentIrql()!=APC_LEVEL)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(result,sizeof(*result));
    result->ReferenceIrql=KeGetCurrentIrql();
    result->Reference=PsReferenceImpersonationToken(actualThread,
        &result->CopyOnOpen,&result->EffectiveOnly,&result->Level);
    result->Impersonating=result->Reference!=NULL;
    return STATUS_SUCCESS;
}

// Any subsequent query is explicitly a later observation of the retained token.
// Retaining the object does not freeze its privileges, groups or ModifiedId.
// No process-primary reference, NULL-thread identity or historical full-token
// reconstruction is claimed by this probe.
_IRQL_requires_(PASSIVE_LEVEL)
VOID SqProbeReleaseAtPassive(_Inout_ SQ_APC_TOKEN_REFERENCE_PROBE* result)
{
    if(result->Reference){PsDereferenceImpersonationToken(result->Reference);
        result->Reference=NULL;}
}

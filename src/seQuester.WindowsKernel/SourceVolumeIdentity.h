#pragma once
// Mount-manager volume identity is cached at instance setup. No volume/name
// lookup is added to process callbacks or the executable-copy loop.
#define SQ_VOLUME_TAG 'vSqS'
#define SQ_VOLUME_CHARS 64
typedef struct _SQ_VOLUME_IDENTITY {
    NTSTATUS Status;
    ULONG NameBytes;
    WCHAR Name[SQ_VOLUME_CHARS];
    BOOLEAN RemoteFilesystem;
} SQ_VOLUME_IDENTITY;
static const FLT_CONTEXT_REGISTRATION SourceVolumeContexts[]={
    {FLT_INSTANCE_CONTEXT,0,NULL,sizeof(SQ_VOLUME_IDENTITY),SQ_VOLUME_TAG},
    {FLT_CONTEXT_END}
};
static VOID SqInitializeVolumeIdentity(PCFLT_RELATED_OBJECTS objects,BOOLEAN remoteFilesystem)
{
    SQ_VOLUME_IDENTITY* context=NULL;UNICODE_STRING name;NTSTATUS status;
    status=FltAllocateContext(objects->Filter,FLT_INSTANCE_CONTEXT,sizeof(*context),NonPagedPoolNx,(PFLT_CONTEXT*)&context);
    if(!NT_SUCCESS(status))return; // Capture later reports missing context explicitly.
    RtlZeroMemory(context,sizeof(*context));
    context->RemoteFilesystem=remoteFilesystem;
    name.Buffer=context->Name;name.Length=0;name.MaximumLength=sizeof(context->Name)-sizeof(WCHAR);
    context->Status=FltGetVolumeGuidName(objects->Volume,&name,NULL);
    if(NT_SUCCESS(context->Status))context->NameBytes=name.Length;
    else RtlZeroMemory(context->Name,sizeof(context->Name));
    // An immutable instance context owns only inline data; no custom cleanup.
    FltSetInstanceContext(objects->Instance,FLT_SET_CONTEXT_KEEP_IF_EXISTS,context,NULL);
    FltReleaseContext(context);
}
#ifdef SQ_REMOTE_FILESYSTEM_DIAGNOSTIC
static BOOLEAN SqIsRemoteInstance(PFLT_INSTANCE instance)
{
    SQ_VOLUME_IDENTITY* context=NULL;BOOLEAN remote=FALSE;
    if(NT_SUCCESS(FltGetInstanceContext(instance,(PFLT_CONTEXT*)&context))){remote=context->RemoteFilesystem;FltReleaseContext(context);}
    return remote;
}
#endif
static VOID SqReadVolumeIdentity(PFLT_INSTANCE instance,SQ_VOLUME_IDENTITY* result)
{
    SQ_VOLUME_IDENTITY* context=NULL;NTSTATUS status;
    RtlZeroMemory(result,sizeof(*result));
    status=FltGetInstanceContext(instance,(PFLT_CONTEXT*)&context);result->Status=status;
    if(NT_SUCCESS(status)){*result=*context;FltReleaseContext(context);}
}

#pragma once
// Bounded PE header classification only. This is neither full image validation
// nor a safety verdict. Filenames do not participate in candidate admission.
static int SqPeOffset(const unsigned char* dos,unsigned int count,unsigned long long size,unsigned int* offset)
{
    unsigned int value;
    if(!dos||!offset||count<64||size<88||dos[0]!='M'||dos[1]!='Z')return 0;
    value=(unsigned int)dos[60]|((unsigned int)dos[61]<<8)|((unsigned int)dos[62]<<16)|((unsigned int)dos[63]<<24);
    if(value<64||(unsigned long long)value>size||size-value<24)return 0;
    *offset=value;return 1;
}
// 0 = unsupported/malformed, 1 = executable candidate, 2 = DLL (not primary).
static int SqPeKind(const unsigned char* header,unsigned int count)
{
    unsigned int flags;
    if(!header||count<24||header[0]!='P'||header[1]!='E'||header[2]||header[3])return 0;
    flags=(unsigned int)header[22]|((unsigned int)header[23]<<8);
    if(flags&0x2000)return 2;
    return (flags&2)?1:0;
}

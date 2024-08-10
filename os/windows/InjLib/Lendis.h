#ifndef __LENDIS_H__
#define __LENDIS_H__

int LengthDisassembler(PBYTE pCode, int *nResult, int *Displacement);
int IsCodeSafe(PBYTE pCode, SIZE_T *CodeLen);

#endif // __LENDIS_H__

/*******************************************************************
 * _GetProcAddress()                                               *
 * Returns address of exported function in library by ordinal.     *
 * NOTE: Original Win9x GetProcAddress() doesn't allow to retreive *
 * Kernel32 functions by ordinal.                                  *
 *                                                                 *
 * GetProcLength()                                                 *
 * Returns the length in bytes of the exported function.           *
 * The length is the difference between the specified function and *
 * the next exported function. If the function is the one with the *
 * higher address use the end of code section to calculate the     *
 * length of the function.                                         *
 *                                                                 *
 * NameToOrdinal()                                                 *
 * Returns the function ordinal for the exported function name.    *
 *                                                                 *
 * (c) A. Miguel Feijao, 1/2/2005                                  *
 *******************************************************************/

#define   _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <limits.h>
#include "GetProcAddress.h"

/*****************************************************************************
 * Returns the corresponding ordinal number for the specified function name. *
 *****************************************************************************/
DWORD NameToOrdinal(HMODULE hModule, LPCSTR lpProcName)
{
    HINSTANCE               pBase;
    PIMAGE_DOS_HEADER       pDOSHeader;
    PIMAGE_NT_HEADERS32     pNTHeader;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    DWORD                   lExportOffset, lExportSize;
    PDWORD                  pNamesArray;
    int                     lNumberOfNames;
    WORD                    nNameIndex;
    LPCSTR                  szName;
    PWORD                   pNameOrdinalsArray;
    int                     i;

    // Library base address
    pBase = hModule;

    // Verify DOS header
    pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) // "MZ"
        return -1;

    // NT Header
    pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE)) // "PE"
        return -1;

    // RVA of export table
    lExportOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    lExportSize = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Pointer to export table
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pBase + lExportOffset);

    // Pointer and length of AddressOfNames array
    pNamesArray = (PDWORD)((DWORD)pBase + pExportDir->AddressOfNames);
    lNumberOfNames = (int)pExportDir->NumberOfNames;

    // Empty names array
    if (lNumberOfNames == 0)
        return -1;

    // Pointer to AddressOfNameOrdinals array
    pNameOrdinalsArray = (PWORD)((DWORD)pBase + pExportDir->AddressOfNameOrdinals);

    // Search for name of function in the NamesArray
    nNameIndex = -1;
    for (i=0; i < lNumberOfNames; i++)
    {
        szName = (char *)((DWORD)pBase + pNamesArray[i]);

        if (!strcmp(szName, lpProcName))
        {
            nNameIndex = i;
            break;
        }
    }

    // Not found
    if (nNameIndex == (WORD)-1)
        return -1;

    // Return ordinal #
    return pNameOrdinalsArray[nNameIndex] + pExportDir->Base;
}


/*********************************************************************
 * Returns the function address of the exported by ordinal function. *
 *********************************************************************/
FARPROC _GetProcAddress(HMODULE hModule, DWORD Ordinal)
{
    HINSTANCE               pBase;
    PIMAGE_DOS_HEADER       pDOSHeader;
    PIMAGE_NT_HEADERS32     pNTHeader;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    DWORD                   lExportOffset, lExportSize;
    PDWORD                  pFunctionArray;
    FARPROC                 pFunctionAddr;

    char                    szForwardedModule[MAX_PATH];
    char*                   szForwardedFunctionName;
    HINSTANCE               hForwardedMod;

    // Library base address
    pBase = hModule;

    // Verify DOS header
    pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) // "MZ"
        return NULL;

    // NT Header
    pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE)) // "PE"
        return NULL;

    // RVA of export table
    lExportOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    lExportSize = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Pointer to export table and export functions array
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pBase + lExportOffset);
    pFunctionArray = (PDWORD)((DWORD)pBase + pExportDir->AddressOfFunctions);

    // Check if requested ordinal # is valid
    if ((Ordinal < pExportDir->Base) ||
        ((Ordinal - pExportDir->Base) > pExportDir->NumberOfFunctions))
        return 0;

    // This works because the export table cannot have gaps
    // (if the ordinal is a gap then the corresponding export table entry contains zero)
    pFunctionAddr = (FARPROC)((DWORD)pBase + pFunctionArray[Ordinal - pExportDir->Base]);

    // Export forward ?
    if (((DWORD)pFunctionAddr >= (DWORD)pExportDir) && ((DWORD)pFunctionAddr < ((DWORD)pExportDir + lExportSize)))
    {
        szForwardedFunctionName = strchr((char *)pFunctionAddr, '.');
        if (!szForwardedFunctionName)
            return NULL;

        // Module (DLL) name and function name
        FillMemory(szForwardedModule, sizeof(szForwardedModule), 0);
        strncpy(szForwardedModule, (char *)pFunctionAddr, szForwardedFunctionName - (char *)pFunctionAddr);
        szForwardedFunctionName++;

        // Load library
        hForwardedMod = LoadLibraryA(szForwardedModule);
        if (!hForwardedMod)
            return NULL;

        // Get addr of function
        pFunctionAddr = _GetProcAddress(hForwardedMod, NameToOrdinal(hForwardedMod, szForwardedFunctionName));
        FreeLibrary(hForwardedMod);
    }

    return pFunctionAddr;
}

/***********************************************************
 * Returns the length of the exported by ordinal function. *
 ***********************************************************/
int GetProcLength(HMODULE hModule, DWORD Ordinal)
{
    HINSTANCE               pBase;
    PIMAGE_DOS_HEADER       pDOSHeader;
    PIMAGE_NT_HEADERS32     pNTHeader;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    PIMAGE_SECTION_HEADER   pImageSectionArray;
    DWORD                   lExportOffset, lExportSize;
    DWORD                   SectionStart, SectionEnd;
    PDWORD                  pFunctionArray;
    FARPROC                 pFunctionAddr, pCurrentFunctionAddr;
    int                     nNumberOfSections;
    int                     i, Diff, Length;
    char                    szForwardedModule[MAX_PATH];
    char*                   szForwardedFunctionName;
    HINSTANCE               hForwardedMod;

    // Library base address
    pBase = hModule;

    // Verify DOS header
    pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) // "MZ"
        return 0;

    // NT Header
    pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE)) // "PE"
        return 0;

    // RVA of export table
    lExportOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    lExportSize = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Pointer to export table and export functions array
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pBase + lExportOffset);
    pFunctionArray = (PDWORD)((DWORD)pBase + pExportDir->AddressOfFunctions);

    // Check if requested ordinal # is valid
    if ((Ordinal < pExportDir->Base) ||
        ((Ordinal - pExportDir->Base) > pExportDir->NumberOfFunctions))
        return 0;

    // This works because the export table cannot have gaps
    // (if the ordinal is a gap then the corresponding export table entry contains zero)
    pFunctionAddr = (FARPROC)((DWORD)pBase + pFunctionArray[Ordinal - pExportDir->Base]);

    // Export forward ?
    if (((DWORD)pFunctionAddr >= (DWORD)pExportDir) && ((DWORD)pFunctionAddr < ((DWORD)pExportDir + lExportSize)))
    {
        szForwardedFunctionName = strchr((char *)pFunctionAddr, '.');
        if (!szForwardedFunctionName)
            return 0;

        // Module (DLL) name and function name
        FillMemory(szForwardedModule, sizeof(szForwardedModule), 0);
        strncpy(szForwardedModule, (char *)pFunctionAddr, szForwardedFunctionName - (char *)pFunctionAddr);
        szForwardedFunctionName++;

        // Load library
        hForwardedMod = LoadLibraryA(szForwardedModule);
        if (!hForwardedMod)
            return 0;

        // Get length of function
        Length = GetProcLength(hForwardedMod, NameToOrdinal(hForwardedMod, szForwardedFunctionName));
        FreeLibrary(hForwardedMod);
        return Length;
    }

    Length = INT_MAX;

    for (i = 1; i <= (int)pExportDir->NumberOfFunctions; i++)
    {
        pCurrentFunctionAddr = (FARPROC)((DWORD)pBase + pFunctionArray[i - pExportDir->Base]);
        Diff = (PBYTE)pCurrentFunctionAddr - (PBYTE)pFunctionAddr;
        if (Diff > 0)
           Length = min(Length, Diff);
    }

    // This is the exported function with the higher address.
    // Use the end of the image section to calculate the length of the function.
    if (Length == INT_MAX)
    {
        pImageSectionArray = IMAGE_FIRST_SECTION(pNTHeader);
        nNumberOfSections = pNTHeader->FileHeader.NumberOfSections;

        // Search all image sections
        for (i=0; i < nNumberOfSections; i++)
        {
            // Code section
            if (pImageSectionArray[i].Characteristics & IMAGE_SCN_CNT_CODE)
            {
                SectionStart = (DWORD)pBase + pImageSectionArray[i].VirtualAddress;
                SectionEnd = SectionStart + pImageSectionArray[i].Misc.VirtualSize;

                // Function lies within this section ?
                if ((DWORD)pFunctionAddr >= SectionStart && (DWORD)pFunctionAddr <= SectionEnd)
                {
                    Length = SectionEnd - (DWORD)pFunctionAddr;
                    break;
                }
            }
        }
    }
    return Length;
}

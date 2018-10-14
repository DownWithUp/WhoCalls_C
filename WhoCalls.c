#include <stdio.h>
#include <Windows.h>
#include <dbghelp.h>

#define IMPORT_TABLE_INDEX  1
CHAR szOutString[MAX_PATH] = { 0 }; // Global Variable 

LPCSTR charsToString(CHAR* pcChars) {
  SIZE_T nRealLength = 0; // Length not including null chars
  /*
  We need to figure out the length of the string because of all the \0's
  we can't just use a regular strlen call.
  */
  for (int i = 0; i <= INFINITE; i++) {
    if (pcChars[i] == 0x00) { // Next char...
      if (pcChars[i + 0x1] == 0x00) { // After 2 0x00 (\0) we know are at the end of the string
        break;
      }
      nRealLength++;
    }
  }
  nRealLength++;
  int j = 0;
  for (int i = 0; i <= (nRealLength * 2); i += 2) {
    szOutString[j] = pcChars[i];
    j++;
   }
  return(&szOutString);
}

LPVOID ImageRvaToVa64(PULONGLONG Base, ULONGLONG Rva, PIMAGE_SECTION_HEADER pRvaCalcSection) {
  /*
  This function is needed because the imagebase in a PE32+ file is a QWORD 
  the normal ImageRvaToVa function doesn't support such variable sizes
  */
  ULONGLONG ullOutput = 0; 
  ullOutput = Rva - pRvaCalcSection->VirtualAddress + pRvaCalcSection->PointerToRawData;
  ullOutput = ullOutput + (BYTE*)Base;
  return(ullOutput);
}
/*
These functions are designed after the ones from dbghelp.dll
I include them here to limit dependencies 
*/
PIMAGE_SECTION_HEADER myImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva) {
  if (NtHeaders == NULL) {
    return(-1); // Basic error checking
  }
  unsigned int nNumOfSections = NtHeaders->FileHeader.NumberOfSections;
  int nCurrentNumOfSections = 0;
  PIMAGE_SECTION_HEADER pISH;
  pISH = (PIMAGE_SECTION_HEADER)((BYTE*)&NtHeaders->OptionalHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);
  if (pISH == NULL) {
    return(-1);
  }
  ULONG ulTemp = 0;
  while (1) {
    ulTemp = pISH->VirtualAddress;
    if (Rva >= ulTemp && Rva < pISH->SizeOfRawData + ulTemp) {
      break;
    }
    ++pISH;
    if (++nCurrentNumOfSections >= nNumOfSections) {
      return(-1);
    }
  }
  return(pISH);
}

PVOID myImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva) {
  PIMAGE_SECTION_HEADER pISH;
  if (NtHeaders == NULL) {
    return(-1); // Basic error checking
	}
  pISH = myImageRvaToSection(NtHeaders, Base, Rva);
  return((BYTE*)Base + (Rva - pISH->VirtualAddress + pISH->PointerToRawData));
}

void showAPIMatch(LPCSTR lpszAPIName, LPCSTR lpszFileName) {
  printf("[! MATCH !] -> %s Is imported by: %s [PRESS RETURN TO CONTINUE]\n", lpszAPIName, lpszFileName);
  getchar();
}

void errorExit(LPCSTR lpszErrorMessage) { 
  // "Fatal" Exit
  printf("[!!!] Error: %s\n", lpszErrorMessage);
  ExitProcess(-1);
}

int main(unsigned int argc, char* argv[]) {
  if (argc != 3) {
    printf("Usage: WhoCalls.exe [API Name] [Path To Query]\n");
    return(-1);
	}
  CHAR szDirectory[MAX_PATH + 0x4] = { 0 };
  if (strlen(argv[2]) >= MAX_PATH) { // Length check in order to 'prevent' buffer overflow
    errorExit("Directory path is too long");
	}
  memcpy(&szDirectory, argv[2], strlen(argv[2])); // szDirectory now has "Path To Query" argument
  strcat(&szDirectory, "\\"); // Add ending slash "\"
  strcat(&szDirectory, "*"); // "*" is a wildcard and it will look for all files
  LPCSTR lpszNameOfAPI = argv[1];
  WIN32_FIND_DATAA winFindData;
  printf("[i] Starting... %s\n", szDirectory);

  HANDLE hFirstFile = FindFirstFileA(szDirectory, &winFindData);
  if (hFirstFile == INVALID_HANDLE_VALUE) {
  FindClose(hFirstFile);
    errorExit("Can't open directory. Check your permissions and path argument");
  }
  CHAR lpszRealFileNameAndPath[MAX_PATH + 0x4] = { 0 };
  do {
    if (!(winFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      LPCSTR lpszRealFileName = charsToString(winFindData.cFileName); // Custom function to turn an array of chars, surrounded by null bytes, to a string
      memset(lpszRealFileNameAndPath, 0x00, MAX_PATH + 0x4); // Null array szRealFileNameAndPath
      memcpy(&lpszRealFileNameAndPath, &szDirectory, strlen(&szDirectory) - 1); // szRealFileNameAndPath now has "Path To Query" argument (-1 for "*")
      strcat(&lpszRealFileNameAndPath, lpszRealFileName); // Add file name to the path
      printf("[i] On file: %s @ %s \n", lpszRealFileName, lpszRealFileNameAndPath);
      HANDLE hFile = CreateFileA(lpszRealFileNameAndPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
      if (hFile != INVALID_HANDLE_VALUE) {
        unsigned char acSigBytes[2] = { 0, 0 };
        unsigned char acValidPESignature[2] = { 0x4D, 0x5A }; // Valid DOS header signature 
        DWORD dwBytesRead;
        ReadFile(hFile, acSigBytes, 0x2, &dwBytesRead, NULL); // First 2 bytes should be DOS header signature
        printf("[i] First bytes: %X, %X", acSigBytes[0], acSigBytes[1]);
        int nResult = memcmp(acSigBytes, acValidPESignature, 0x2);
        if (nResult == 0) {
          printf(" | File is valid!\n");
          HANDLE hFileMapObj = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
          LPDWORD lpMemory = MapViewOfFile(hFileMapObj, FILE_MAP_READ, 0, 0, 0);
          PIMAGE_DOS_HEADER pIDH = lpMemory; // DOS_HEADER starts at the beginning of the file  
          PIMAGE_NT_HEADERS32 pINH = (BYTE*)lpMemory + pIDH->e_lfanew;
          /*
          Now we see if the file is PE(32-bit) or PE32+ (64-bit)
          IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
          IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
          SRC: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
          */
          // printf("value of lpMemory: %X\n", lpMemory); //Debug only. Shows the location in memory where the file mapping starts
          if (pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) { // 32-Bit (PE32)
            printf("[i] File is 32-Bit\n");
            IMAGE_DATA_DIRECTORY IDDImports;
            /*
            First we check if the import table is present in the image data directory array, which is always 16 sections.
            If the sections are not filled they are zeroed out, but still present in the file.
            SRC: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_data_directory
            */
            IDDImports = pINH->OptionalHeader.DataDirectory[IMPORT_TABLE_INDEX]; // File has Import table
	          if (IDDImports.VirtualAddress == 0x0) {
		          printf("[!] File has invalid import table address");
              goto skipFile;
	          }
            PIMAGE_SECTION_HEADER pISHImports = myImageRvaToVa(pINH, lpMemory, IDDImports.VirtualAddress);
            PIMAGE_SECTION_HEADER pISHImportsForName = myImageRvaToSection(pINH, lpMemory, IDDImports.VirtualAddress);
            if (pISHImportsForName->Name == 0x00) {
              printf("[!] Invalid or non existing section name");
              CloseHandle(hFileMapObj); // Free before moving to next file
              UnmapViewOfFile(lpMemory); // Free before moving to next file
              goto skipFile;
            }
            printf("[i] Name of section: ");
            for (int i = 0; i <= IMAGE_SIZEOF_SHORT_NAME; i++) {
              if (pISHImportsForName->Name[i] == 0x00) {
                break; // We reached the end of the "Name" string
              }
              printf("%c", pISHImportsForName->Name[i]);
            }
            printf("\n");
            printf("[i] Searching for import: %s\n", lpszNameOfAPI);
            PIMAGE_IMPORT_DESCRIPTOR pIID = pISHImports;
            PIMAGE_THUNK_DATA32 pITD32;
            PIMAGE_IMPORT_BY_NAME pIIBN;
            for (; pIID->Name != 0x0; pIID++) { // Loop through each Image Import Descriptor in the import section
            /*
            The name "Characteristics" is used in Winnt.h, but no longer describes this field.
            SRC: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-directory-table
            */
              LPDWORD lpDLLName = myImageRvaToVa(pINH, lpMemory, pIID->Name);
              printf("[i] Checking DLL: %s\n", lpDLLName);
              /*
              Use OriginalFirstThunk over FirstThunk, as the file may be using
              DLL import binding. Apparently Original First Think is also an optional array.
              */
              if (pIID->OriginalFirstThunk == 0x00) { // Optional 
                pITD32 = myImageRvaToVa(pINH, lpMemory, pIID->FirstThunk);
              }
              else if (pIID->OriginalFirstThunk != pIID->FirstThunk) { // Better than FirstThunk
                pITD32 = myImageRvaToVa(pINH, lpMemory, pIID->OriginalFirstThunk);
              }
              else { //Best bet is OriginalFirstThunk
                pITD32 = myImageRvaToVa(pINH, lpMemory, pIID->OriginalFirstThunk);
              }
              for (; pITD32->u1.AddressOfData != 0x00; pITD32++) { // Look through each Image Thunk Data and read names of imported APISz
                /*
                API is possibly imported by ordinal. So we need to check the most most significant bit
                and see if it is 0x8
                SRC: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-directory-table
                */
                if ((ULONGLONG)pITD32->u1.AddressOfData >= 0x80000000) {
                  printf("\t-API imported by ordinal: %X\n", pITD32->u1.AddressOfData);
                }
                else {
                  pIIBN = myImageRvaToVa(pINH, lpMemory, pITD32->u1.AddressOfData);
                  printf("\t-API name: %s\n", pIIBN->Name);
                  if (strcmp(pIIBN->Name, lpszNameOfAPI) == 0) {
                    showAPIMatch(lpszNameOfAPI, lpszRealFileName);
                  }
                }
              }
            }
          }
          else if (pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { // 64-Bit (PE32+)
            printf("[i] File is 64-Bit\n"); 
            PIMAGE_NT_HEADERS64 pINH64 = (BYTE*)lpMemory + pIDH->e_lfanew; // Without cast, you would be adding to sizeof(lpMemory)!
            IMAGE_DATA_DIRECTORY IDDImports;
            /*
            First we check if the import table is present in the image data directory array, which is always 16 sections.
            If the sections are not filled they are zeroed out, but still present in the file.
            SRC: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_data_directory
            */
            IDDImports = pINH64->OptionalHeader.DataDirectory[IMPORT_TABLE_INDEX]; //File has Import table
            if (IDDImports.VirtualAddress == 0x0) {
              printf("[!] File has invalid import table address");
              goto skipFile;
            }
            PIMAGE_SECTION_HEADER pISHImports = myImageRvaToVa(pINH64, lpMemory, IDDImports.VirtualAddress);
            PIMAGE_SECTION_HEADER pISHImportsForName = myImageRvaToSection(pINH64, lpMemory, IDDImports.VirtualAddress);
            if (pISHImportsForName->Name == 0x00) {
              printf("[!] Invalid or non existing section name");
              CloseHandle(hFileMapObj); // Free before moving to next file
              UnmapViewOfFile(lpMemory); // Free before moving to next file
              goto skipFile;
            }
            printf("[i] Name of section: ");
            for (int i = 0; i <= IMAGE_SIZEOF_SHORT_NAME; i++) {
              if (pISHImportsForName->Name[i] == 0x00) {
                break; // We reached the end of the "Name" string
              }
              printf("%c", pISHImportsForName->Name[i]);
            }
            printf("\n");
            printf("[i] Searching for import: %s\n", lpszNameOfAPI);
            PIMAGE_IMPORT_DESCRIPTOR pIID = pISHImports;
            printf("Checking virtual address: %X\n", &pIID->Name);
            PIMAGE_THUNK_DATA64 pITD64;
            PIMAGE_IMPORT_BY_NAME pIIBN;
            for (; pIID->Name != 0x0; pIID++) { // Loop through each Image Import Descriptor in the import section
              /*
              The name "Characteristics" is used in Winnt.h, but no longer describes this field.
              SRC: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-directory-table
              */
              LPDWORD lpDLLName = myImageRvaToVa(pINH64, lpMemory, pIID->Name);
              printf("[i] Checking DLL: %s\n", lpDLLName);
              /*
              Use OriginalFirstThunk over FirstThunk, as the file may be using
              DLL import binding. Apparently Original First Think is also an optional array.
              */
              if (pIID->OriginalFirstThunk == 0x00) { // Optional 
                pITD64 = myImageRvaToVa(pINH64, lpMemory, pIID->FirstThunk);
              }
              else if (pIID->OriginalFirstThunk != pIID->FirstThunk) { // Better than FirstThunk
                pITD64 = myImageRvaToVa(pINH64, lpMemory, pIID->OriginalFirstThunk);
              }
              else { //Best bet is OriginalFirstThunk
                pITD64 = myImageRvaToVa(pINH64, lpMemory, pIID->OriginalFirstThunk); 
              }
              for (; pITD64->u1.AddressOfData != 0x00; pITD64++) { // Look through each Image Thunk Data and read names of imported APISz
                /*
                API is possibly imported by ordinal. So we need to check the most most significant bit
                and see if it is 0x8
                SRC: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-directory-table
                */
                if ((ULONGLONG)pITD64->u1.AddressOfData >= 0x8000000000000000) {
                  printf("\t-API imported by ordinal: %X\n", pITD64->u1.AddressOfData);
                }
                else {
                  pIIBN = ImageRvaToVa64(lpMemory, pITD64->u1.AddressOfData, pISHImportsForName); // Custom function
                  printf("\t-API name: %s\n", pIIBN->Name);
                  if (strcmp(pIIBN->Name, lpszNameOfAPI) == 0) {
                    showAPIMatch(lpszNameOfAPI, lpszRealFileName);
                  }
                }
              }
            }
          }
          else {
            errorExit("Optional Header could not be read!");
          }
          CloseHandle(hFileMapObj);
          UnmapViewOfFile(lpMemory);
        }
        else {
        skipFile:;
          printf(" | INVALID PE file\nMoving to next file...\n\n");
          CloseHandle(hFile);
        }
      }
      else {
        printf("[!] Unable to open file... CreateFile returned: 0x%X\n", hFile);
        printf("Last Error Code: %X (Press Enter)\n", GetLastError());
        getchar();
        goto skipFile; 
      }
      CloseHandle(hFile);
    }
  } while (FindNextFileW(hFirstFile, &winFindData) != 0);
  printf("[!] End of directory\n");
  FindClose(hFirstFile); // MSDN says don't use normal close handle
  return(0); // Success?
}

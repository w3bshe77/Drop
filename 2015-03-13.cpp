#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <Windows.h>
#pragma warning(disable:4996)
LPVOID ReadPEFile(LPSTR lpszFile)
{
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pFileBuffer = NULL;

	//打开文件	
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		printf(" 无法打开 EXE 文件! ");
		return NULL;
	}
	//读取文件大小		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区	
	pFileBuffer = malloc(fileSize);

	if (!pFileBuffer)
	{
		printf(" 分配空间失败! ");
		fclose(pFile);
		return NULL;
	}
	//将文件数据读取到缓冲区	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n)
	{
		printf(" 读取数据失败! ");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//关闭文件	
	fclose(pFile);
	return pFileBuffer;
}

VOID PrintNTHeaders()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader2 = NULL;

	pFileBuffer = ReadPEFile((LPSTR)"R:\\sogou_pinyin_93f.exe");
	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//打印DOC头	
	printf("pDosHeader：%x\n", pDosHeader);
	printf("********************DOS头********************\n");
	printf("MZ标志：%x\n", pDosHeader->e_magic);
	printf("PE偏移：%x\n", pDosHeader->e_lfanew);
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer/*4D*/ + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	//打印NT头	
	printf("********************NT头********************\n");
	printf("NT：%x\n", pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("********************PE头********************\n");
	printf("PE：%x\n", pPEHeader->Machine);
	printf("节的数量：%x\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader：%x\n", pPEHeader->SizeOfOptionalHeader);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PE头********************\n");
	printf("OPTION_PE：%x\n", pOptionHeader->Magic); 
	printf("ImageBase：%x\n", pOptionHeader->ImageBase);
	printf("AddressOfEntryPoint：%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("内存对齐：%x\n", pOptionHeader->SectionAlignment);
	printf("文件对齐：%x\n", pOptionHeader->FileAlignment);
	printf("内存中PE文件的尺寸（是内存对齐的整数倍）：%x\n", pOptionHeader->SizeOfImage);
	printf("PE头+节表的尺寸：%x\n", pOptionHeader->SizeOfHeaders);
	printf("Rva数量：%x\n", pOptionHeader->NumberOfRvaAndSizes);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + 0xE0);
	printf("********************SECTION1 HEARDER********************\n");
	printf("第1个SECTION：%s\n", pSectionHeader->Name);
	printf("SECTION文件真实尺寸VirtualSize：%x\n", pSectionHeader->Misc.VirtualSize);
	printf("SECTION文件对齐尺寸SizeOfRawData：%x\n", pSectionHeader->SizeOfRawData);
	printf("SECTION内存偏移地址VirtualAddress：%x  加上ImageBase后是实际Adress: %x\n",
		pSectionHeader->VirtualAddress, 
		pOptionHeader->ImageBase + pSectionHeader->VirtualAddress);
	printf("SECTION文件偏移地址PointerToRawData：%x\n", pSectionHeader->PointerToRawData);
	printf("SECTION文件属性Characteristics：%x\n", pSectionHeader->Characteristics);
	printf("SECTION文件真实起止地址：%x--%x\n", pSectionHeader->PointerToRawData,
		pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize);
	printf("SECTION文件对齐起止地址：%x--%x\n", pSectionHeader->PointerToRawData,
		pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData);
	printf("SECTION内存真实起止地址：%x--%x\n", pOptionHeader->ImageBase + pSectionHeader->VirtualAddress,
		pOptionHeader->ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);

	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
		printf("********************SECTION%d HEARDER********************\n",i+1);
		printf("第%d个SECTION：%s\n", i+1, pSectionHeader->Name);
		printf("SECTION文件真实尺寸VirtualSize：%x\n", pSectionHeader->Misc.VirtualSize);
		printf("SECTION文件对齐尺寸SizeOfRawData：%x\n", pSectionHeader->SizeOfRawData);
		printf("SECTION内存偏移地址VirtualAddress：%x  加上ImageBase后是实际Adress: %x\n", pSectionHeader->VirtualAddress,
			pOptionHeader->ImageBase+ pSectionHeader->VirtualAddress);
		printf("SECTION文件偏移地址PointerToRawData：%x\n", pSectionHeader->PointerToRawData);
		printf("SECTION文件属性Characteristics：%x\n", pSectionHeader->Characteristics);
		printf("SECTION文件真实起止地址：%x--%x\n", pSectionHeader->PointerToRawData,
			pSectionHeader->PointerToRawData+ pSectionHeader->Misc.VirtualSize);
		printf("SECTION文件对齐起止地址：%x--%x\n", pSectionHeader->PointerToRawData, 
			pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData);	
		printf("SECTION内存真实起止地址：%x--%x\n", pOptionHeader->ImageBase + pSectionHeader->VirtualAddress,
			pOptionHeader->ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	}

	//释放内存	
	free(pFileBuffer);
}
int main()
{
	PrintNTHeaders();
	system("pause");
	return 0;
}

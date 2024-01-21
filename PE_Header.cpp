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

	//���ļ�	
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		printf(" �޷��� EXE �ļ�! ");
		return NULL;
	}
	//��ȡ�ļ���С		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//���仺����	
	pFileBuffer = malloc(fileSize);

	if (!pFileBuffer)
	{
		printf(" ����ռ�ʧ��! ");
		fclose(pFile);
		return NULL;
	}
	//���ļ����ݶ�ȡ��������	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n)
	{
		printf(" ��ȡ����ʧ��! ");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//�ر��ļ�	
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
		printf("�ļ���ȡʧ��\n");
		return;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//��ӡDOCͷ	
	printf("pDosHeader��%x\n", pDosHeader);
	printf("********************DOSͷ********************\n");
	printf("MZ��־��%x\n", pDosHeader->e_magic);
	printf("PEƫ�ƣ�%x\n", pDosHeader->e_lfanew);
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer/*4D*/ + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	//��ӡNTͷ	
	printf("********************NTͷ********************\n");
	printf("NT��%x\n", pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("********************PEͷ********************\n");
	printf("PE��%x\n", pPEHeader->Machine);
	printf("�ڵ�������%x\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader��%x\n", pPEHeader->SizeOfOptionalHeader);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PEͷ********************\n");
	printf("OPTION_PE��%x\n", pOptionHeader->Magic); 
	printf("ImageBase��%x\n", pOptionHeader->ImageBase);
	printf("AddressOfEntryPoint��%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("�ڴ���룺%x\n", pOptionHeader->SectionAlignment);
	printf("�ļ����룺%x\n", pOptionHeader->FileAlignment);
	printf("�ڴ���PE�ļ��ĳߴ磨���ڴ���������������%x\n", pOptionHeader->SizeOfImage);
	printf("PEͷ+�ڱ�ĳߴ磺%x\n", pOptionHeader->SizeOfHeaders);
	printf("Rva������%x\n", pOptionHeader->NumberOfRvaAndSizes);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + 0xE0);
	printf("********************SECTION1 HEARDER********************\n");
	printf("��1��SECTION��%s\n", pSectionHeader->Name);
	printf("SECTION�ļ���ʵ�ߴ�VirtualSize��%x\n", pSectionHeader->Misc.VirtualSize);
	printf("SECTION�ļ�����ߴ�SizeOfRawData��%x\n", pSectionHeader->SizeOfRawData);
	printf("SECTION�ڴ�ƫ�Ƶ�ַVirtualAddress��%x  ����ImageBase����ʵ��Adress: %x\n",
		pSectionHeader->VirtualAddress, 
		pOptionHeader->ImageBase + pSectionHeader->VirtualAddress);
	printf("SECTION�ļ�ƫ�Ƶ�ַPointerToRawData��%x\n", pSectionHeader->PointerToRawData);
	printf("SECTION�ļ�����Characteristics��%x\n", pSectionHeader->Characteristics);
	printf("SECTION�ļ���ʵ��ֹ��ַ��%x--%x\n", pSectionHeader->PointerToRawData,
		pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize);
	printf("SECTION�ļ�������ֹ��ַ��%x--%x\n", pSectionHeader->PointerToRawData,
		pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData);
	printf("SECTION�ڴ���ʵ��ֹ��ַ��%x--%x\n", pOptionHeader->ImageBase + pSectionHeader->VirtualAddress,
		pOptionHeader->ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);

	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
		printf("********************SECTION%d HEARDER********************\n",i+1);
		printf("��%d��SECTION��%s\n", i+1, pSectionHeader->Name);
		printf("SECTION�ļ���ʵ�ߴ�VirtualSize��%x\n", pSectionHeader->Misc.VirtualSize);
		printf("SECTION�ļ�����ߴ�SizeOfRawData��%x\n", pSectionHeader->SizeOfRawData);
		printf("SECTION�ڴ�ƫ�Ƶ�ַVirtualAddress��%x  ����ImageBase����ʵ��Adress: %x\n", pSectionHeader->VirtualAddress,
			pOptionHeader->ImageBase+ pSectionHeader->VirtualAddress);
		printf("SECTION�ļ�ƫ�Ƶ�ַPointerToRawData��%x\n", pSectionHeader->PointerToRawData);
		printf("SECTION�ļ�����Characteristics��%x\n", pSectionHeader->Characteristics);
		printf("SECTION�ļ���ʵ��ֹ��ַ��%x--%x\n", pSectionHeader->PointerToRawData,
			pSectionHeader->PointerToRawData+ pSectionHeader->Misc.VirtualSize);
		printf("SECTION�ļ�������ֹ��ַ��%x--%x\n", pSectionHeader->PointerToRawData, 
			pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData);	
		printf("SECTION�ڴ���ʵ��ֹ��ַ��%x--%x\n", pOptionHeader->ImageBase + pSectionHeader->VirtualAddress,
			pOptionHeader->ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	}

	//�ͷ��ڴ�	
	free(pFileBuffer);
}
int main()
{
	PrintNTHeaders();
	system("pause");
	return 0;
}
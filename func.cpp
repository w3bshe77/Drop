#include "func.h"

PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_NT_HEADERS pNTHeader = NULL;
PIMAGE_FILE_HEADER pPEHeader = NULL;
PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
LPVOID pTempImageBuffer = NULL;
IMAGE_DATA_DIRECTORY PEtables; //������
PIMAGE_EXPORT_DIRECTORY Exportable = NULL;
PIMAGE_EXPORT_DIRECTORY TrueExport = NULL;
PIMAGE_BASE_RELOCATION  Reloctiontable = NULL;
PIMAGE_BASE_RELOCATION  TrueReloc = NULL;
char file_path[] = "R:\\demotll2.dll";
char write_file_path[] = "D:\\demotll2_New.dll";
BYTE SectionTable[] =
{
	0x2E,0x4E,0x65,0x77,0x53,0x65,0x63,00,//Name
	00,0x10,00,00,//Misc
	00,0x70,0x02,00,//VirtualAddress
	00,0x10,00,00,//SizeOfRawData
	00,0x70,0x02,00,//PointerToRawData
	00,00,00,00,
	00,00,00,00,
	00,00,
	00,00,
	0x20,00,00,0x60//Characteristics
};
BYTE shellcode[] =
{
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00
};
/*
��һ������DLL������һ���ڣ��������������FOA

�ڶ���������AddressOfFunctions

	���ȣ�4*NumberOfFunctions

������������AddressOfNameOrdinals

	���ȣ�NumberOfNames*2

���Ĳ�������AddressOfNames

	���ȣ�NumberOfNames*4

���岽���������еĺ�����

	���Ȳ�ȷ��������ʱֱ���޸�AddressOfNames

������������IMAGE_EXPORT_DIRECTORY�ṹ


���߲����޸�IMAGE_EXPORT_DIRECTORY�ṹ�е�

	AddressOfFunctions

	AddressOfNameOrdinals

	AddressOfNames

�ڰ˲����޸�Ŀ¼���е�ֵ��ָ���µ�IMAGE_EXPORT_DIRECTORY

*/
/*��ȡ�ļ�*/
DWORD ReadPEFile(const char* lpszFile, OUT PVOID* pFileBuffer)
{
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pTempFileBuffer = NULL;

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
	printf("================ReadPEFile================\n");
	printf("fileSize:%08X\n", fileSize);

	fseek(pFile, 0, SEEK_SET);

	//���仺����	
	pTempFileBuffer = malloc(fileSize);

	if (!pTempFileBuffer)
	{
		printf(" ����ռ�ʧ��! ");
		fclose(pFile);
		return NULL;
	}
	//���ļ����ݶ�ȡ��������	
	memset(pTempFileBuffer, '\0', fileSize);
	size_t n = fread(pTempFileBuffer, fileSize, 1, pFile);
	if (!n)
	{
		printf(" ��ȡ����ʧ��! ");
		free(pTempFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//�ر��ļ�	

	*pFileBuffer = pTempFileBuffer;
	pTempFileBuffer = NULL;
	fclose(pFile);
	return fileSize;
}
/*�������*/
DWORD CopyFileBufferToImageBuffer(LPVOID pFileBuffer, OUT PVOID* pImageBuffer)
{

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTempImageBuffer = NULL;

	if (pFileBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer/*4D*/ + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);

	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;

	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(&pNTHeader->OptionalHeader);


	//����Ŀռ�������imagesize�Ĵ�С
	DWORD pImagesize = pOptionHeader->SizeOfImage;

	//printf("CopyFileBufferToImageBuffer__pOptionHeader->SizeOfImage:%x\n", pImagesize);
	pTempImageBuffer = malloc(pImagesize);
	if (!pTempImageBuffer)
	{
		printf(" ����ռ�ʧ��! ");
	}
	//�����0
	memset(pTempImageBuffer, 0, pImagesize);
	//����pFileBuffer��pImageBuffer ������СΪpOptionHeader->SizeOfHeaders
	memcpy(pTempImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);


	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + (DWORD)pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		if (true)
		{

		}
		memcpy((void*)((DWORD)pTempImageBuffer + (DWORD)pTempSectionHeader->VirtualAddress), (void*)((DWORD)pFileBuffer + (DWORD)pTempSectionHeader->PointerToRawData), pTempSectionHeader->SizeOfRawData);
	}
	*pImageBuffer = pTempImageBuffer;
	pTempImageBuffer = NULL;

	return pImagesize;

	//����pImageBuffer��NewBuffer

}
/*����imagebufferһ��sectionaligment*/
DWORD AddImageBuffer(LPVOID pImageBuffer, OUT PVOID* pNewImageBuffer) {
	printf("---------------ExpansionBuffer---------------\n");
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (pImageBuffer == NULL)
	{
		printf("ExpansionBuffer������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("ExpansionBuffer������Ч��MZ��־\n");
		free(pImageBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pImageBuffer/*4D*/ + (DWORD)pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("ExpansionBuffer������Ч��PE��־\n");
		free(pImageBuffer);
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	DWORD NewFilesize = pOptionHeader->SizeOfImage + pOptionHeader->SectionAlignment;
	printf("NewFilesize:%08x\n pOptionHeader->SizeOfImage:%08x\n pOptionHeader->SectionAlignment:%08x\n", NewFilesize, pOptionHeader->SizeOfImage, pOptionHeader->SectionAlignment);
	LPVOID pNewBuffer = malloc(NewFilesize);
	if (!pNewBuffer)
	{
		printf(" ����ռ�ʧ��! ");
	}
	else
	{
		memset(pNewBuffer, 0, NewFilesize);
		memcpy(pNewBuffer, pImageBuffer, (size_t)pOptionHeader->SizeOfImage);
	}
	*pNewImageBuffer = pNewBuffer;
	pNewBuffer = NULL;
	return NewFilesize;
}
/*��filebuff�Ļ���������һ����*/
DWORD AddFileBuffer(LPVOID pFileBuffer, DWORD filesize, OUT PVOID* pNewFileBuffer)
{
	/*
		1) ���һ���µĽ�(����copyһ��)

		2) �������ں��� ���һ���ڴ�С��000

		3) �޸�PEͷ�нڵ�����

		4) �޸�sizeOfImage�Ĵ�С

		5) ��ԭ�����ݵ��������һ���ڵ�����(�ڴ�����������).

		6�����������ڱ������

	sizeofheaders +lastsection.pointtorawdata + lastsection.sizeofrawdata + FileAligment * 2  ?
	sizeof(pFielBuffer) + FileAligment * 2  ?

	pNewSectionHeader->PointerToRawData = t_LastSectionHeader->PointerToRawData + t_LastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData = pOptionHeader.FileAligment;
	pNewSectionHeader->VirtualAddress = t_LastSectionHeader->VirtualAddress + t_LastSectionHeader->SizeOfRawData;

	*/
	IniPefileDate(pFileBuffer);
	printf("sizeof pFileBuffer:%X\npOptionHeader->SectionAlignment * 2:%X\nfilesize + pOptionHeader->SectionAlignment * 2:%X\n", filesize, pOptionHeader->SectionAlignment * 2, filesize + pOptionHeader->SectionAlignment * 2);
	//1) ���һ���µĽ�(����copyһ��)
	DWORD pNewFilesize = (DWORD)filesize + pOptionHeader->SectionAlignment * 2;
	LPVOID pNewBuffer = malloc(pNewFilesize);
	printf("sizeof pNewFilesize:%X\npOptionHeader->SizeOfImage:%X\n", pNewFilesize, pOptionHeader->SizeOfImage);
	if (!pNewBuffer)
	{
		printf(" ����ռ�ʧ��! ");
	}
	else
	{
		memset(pNewBuffer, 0, pNewFilesize);
		memcpy(pNewBuffer, pFileBuffer, (size_t)pOptionHeader->SizeOfImage);
	}
	*pNewFileBuffer = pNewBuffer;
	pNewBuffer = NULL;
	return pNewFilesize;
}
/*filebuff����SectionTable*/
void ChangePEinfo(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer)
{
	IniPefileDate(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	if ((PBYTE)pOptionHeader->SizeOfHeaders - (PBYTE)pDosHeader->e_lfanew - 4 - IMAGE_SIZEOF_FILE_HEADER - pPEHeader->SizeOfOptionalHeader - pPEHeader->NumberOfSections * 40 < 80)
	{
		printf("�ռ䲻�㣬�޷������ڱ�");
		exit(0);
	}

	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections;
	//printf("pNewSectionHeader = %08X\npSectionHeader = %08X\npPEHeader->NumberOfSections = %X\npSectionHeader + pPEHeader->NumberOfSections = %08X\n", pNewSectionHeader, pSectionHeader,pPEHeader->NumberOfSections, pSectionHeader + pPEHeader->NumberOfSections);
	//2) �������ں��� ���һ���ڴ�С��0
	memset(pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER) * 2);
	//3) �޸�PEͷ�нڵ�����
	pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
	//4) �޸�sizeOfImage�Ĵ�С
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + pOptionHeader->SectionAlignment;
	// 5) ��ԭ�����ݵ��������һ���ڵ�����.

	PBYTE TableBegin = (PBYTE)(pNewSectionHeader);
	//PBYTE TableBegin1 = (PBYTE)((DWORD)pLastSectionHeader + 0x28);
	//printf("lastSectionheader:%s\nTableBegin:%08x\nTableBegin1:%08x\n SectionTable:%08x\nSECTIONTABLELENTH:%08x\n\n", pLastSectionHeader->Name, TableBegin, TableBegin1,SectionTable, SECTIONTABLELENTH);
	//printf("pPEHeader->NumberOfSections:%d\npOptionHeader->SizeOfImage:%08x\nsizeof(IMAGE_SECTION_HEADER):%x\n", pPEHeader->NumberOfSections, pOptionHeader->SizeOfImage, sizeof(IMAGE_SECTION_HEADER));
	memcpy(TableBegin, SectionTable, SECTIONTABLELENTH);
	printf("\n\npNewSectionHeader->Name:%s-->VirtualSize:%08X-->VirtualAddress:%08X-->SizeOfRawData:%08X-->PointerToRawData:%08X\n\n", 
		pNewSectionHeader->Name, 
		pNewSectionHeader->Misc.VirtualSize,
		pNewSectionHeader->VirtualAddress, 
		pNewSectionHeader->SizeOfRawData, 
		pNewSectionHeader->PointerToRawData);

	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	//printf("NewPointerToRawData= %08X\nLastPointerToRawData = %08X\nLastSizeOfRawData = %08X\nLastPointerToRawData +LastSizeOfRawData = %08X\n",pNewSectionHeader->PointerToRawData, pLastSectionHeader->PointerToRawData, pLastSectionHeader->SizeOfRawData, pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData);
	pNewSectionHeader->SizeOfRawData = pOptionHeader->FileAlignment;
	if (((int)pLastSectionHeader->Misc.VirtualSize - (int)pOptionHeader->SectionAlignment) > 0)
	{
		pNewSectionHeader->VirtualAddress = (DWORD)pLastSectionHeader->VirtualAddress + ((((DWORD)pLastSectionHeader->Misc.VirtualSize / (DWORD)pOptionHeader->SectionAlignment) + 1) * (DWORD)pOptionHeader->SectionAlignment);
	}
	else
	{
		pNewSectionHeader->VirtualAddress = (DWORD)pLastSectionHeader->VirtualAddress + (DWORD)pOptionHeader->SectionAlignment;
	}
	pNewSectionHeader->Characteristics = pSectionHeader->Characteristics;
	pNewSectionHeader->Misc.VirtualSize = pOptionHeader->SectionAlignment;

	printf("\n\npNewSectionHeader->Name:%s-->VirtualSize:%08X-->VirtualAddress:%08X-->SizeOfRawData:%08X-->PointerToRawData:%08X\n\n",
		pNewSectionHeader->Name,
		pNewSectionHeader->Misc.VirtualSize,
		pNewSectionHeader->VirtualAddress,
		pNewSectionHeader->SizeOfRawData,
		pNewSectionHeader->PointerToRawData);
	memset((PDWORD)((DWORD)pFileBuffer + pNewSectionHeader->PointerToRawData), 0, pOptionHeader->FileAlignment);
	*pNewFileBuffer = pFileBuffer;
	pFileBuffer = NULL;
}
/*imagebuffer����SectionTable+shellcode*/
BOOL NewSections(LPVOID pNewImageBuffer, OUT PVOID* pNew_ImageBuffer)
{
	printf("---------------NewSections---------------\n");
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (pNewImageBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pNewImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pNewImageBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pNewImageBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pNewImageBuffer/*4D*/ + (DWORD)pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		free(pNewImageBuffer);
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNewImageBuffer + pDosHeader->e_lfanew);

	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;

	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER lastSectionheader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	if ((PBYTE)pOptionHeader->SizeOfHeaders - (PBYTE)pDosHeader->e_lfanew - 4 - IMAGE_SIZEOF_FILE_HEADER - pPEHeader->SizeOfOptionalHeader - pPEHeader->NumberOfSections * 40 < 80)
	{
		printf("�ռ䲻�㣬�޷������ڱ�");
		exit(0);
	}
	PBYTE TableBegin = (PBYTE)((DWORD)lastSectionheader + 0x28);
	printf("lastSectionheader:%s\nTableBegin:%08x\n SectionTable:%08x\nSECTIONTABLELENTH:%08x\n", lastSectionheader->Name, TableBegin, SectionTable, SECTIONTABLELENTH);


	//memset((PBYTE)((DWORD)TableBegin + SECTIONTABLELENTH), 0, SECTIONTABLELENTH);
	memset((LPVOID)(pSectionHeader + pPEHeader->NumberOfSections + 1), 0,
		sizeof(IMAGE_SECTION_HEADER));
	pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + pOptionHeader->SectionAlignment;
	printf("pPEHeader->NumberOfSections:%d\npOptionHeader->SizeOfImage:%08x\n", pPEHeader->NumberOfSections, pOptionHeader->SizeOfImage);
	memcpy(TableBegin, SectionTable, SECTIONTABLELENTH);
	PBYTE codebegin;
	/*
	�����ڵķ�ʽ������հ״��ķ�ʽ��һ���������ڱ���Ҫ�����ڴ������ļ�����Ĵ�С

	����ڴ������1000���ļ�������200���Ǿ�Ҫ��rva+��VirtualSize/SectionAlignment��*SectionAlignment ������
	���������VirtualSize/SectionAlignment��*SectionAlignment����Ϊ0 ��Ϊ����ĳ��������С���� ��int���� ����float��
	����Ҫ�����������

	����ڴ������ļ����붼��1000��С���Ǿ�ֻ��ҪSectionAlignment����filealignment��ֵ��������ʵ��һ��
	*/

	if (((int)lastSectionheader->Misc.VirtualSize - (int)pOptionHeader->SectionAlignment) > 0)
	{
		codebegin = (PBYTE)((DWORD)pNewImageBuffer + (DWORD)lastSectionheader->VirtualAddress + (((DWORD)lastSectionheader->Misc.VirtualSize / (DWORD)pOptionHeader->SectionAlignment) + 1) * (DWORD)pOptionHeader->SectionAlignment);
		printf("SectionAlignment < VirtualSize ��codebegin:%08x\npOptionHeader->SectionAlignment:%08x\n", codebegin, pOptionHeader->SectionAlignment);
	}
	else
	{
		codebegin = (PBYTE)((DWORD)pNewImageBuffer + (DWORD)lastSectionheader->VirtualAddress + (DWORD)pOptionHeader->SectionAlignment);
		printf("SectionAlignment > VirtualSize ��codebegin:%08x\npOptionHeader->SectionAlignment:%08x\n", codebegin, pOptionHeader->SectionAlignment);
	}
	DWORD Miscaddr = pOptionHeader->SectionAlignment;
	*(PDWORD)(TableBegin + 8) = Miscaddr;
	DWORD VirAddr = 0;
	if (((int)lastSectionheader->Misc.VirtualSize - (int)pOptionHeader->SectionAlignment) > 0)
	{
		VirAddr = (DWORD)lastSectionheader->VirtualAddress + ((((DWORD)lastSectionheader->Misc.VirtualSize / (DWORD)pOptionHeader->SectionAlignment) + 1) * (DWORD)pOptionHeader->SectionAlignment);
	}
	else
	{
		VirAddr = (DWORD)lastSectionheader->VirtualAddress + (DWORD)pOptionHeader->SectionAlignment;
	}

	printf("VirAddr:%08x\nlastSectionheader->VirtualAddress:%08x\n", VirAddr, lastSectionheader->VirtualAddress);
	*(PDWORD)(TableBegin + 0xC) = VirAddr;
	DWORD sord = pOptionHeader->FileAlignment;
	*(PDWORD)(TableBegin + 0x10) = sord;
	DWORD PTRD = (DWORD)lastSectionheader->SizeOfRawData + (DWORD)lastSectionheader->PointerToRawData;
	*(PDWORD)(TableBegin + 0x14) = PTRD;

	for (size_t i = 0; i < SECTIONTABLELENTH; i++)
	{
		printf("%x ", TableBegin[i]);

	}

	memcpy(codebegin, shellcode, SHELLCODELENTH);
	DWORD calladdr = MESSAGEBOXADDRESS - (pOptionHeader->ImageBase + (((DWORD)codebegin + 0xD) - (DWORD)pNewImageBuffer));
	// codebegin+0xD ���� shellcode �� 0xE9��λ��

	*(PDWORD)(codebegin + 9) = calladdr;
	// codebegin+9 ���� shellcode �� 0xE8��λ��

	printf("\nE8:%x\n", *(PDWORD)(codebegin + 9));
	DWORD jmpaddr = ((DWORD)pOptionHeader->ImageBase + (DWORD)pOptionHeader->AddressOfEntryPoint) - ((DWORD)pOptionHeader->ImageBase + (((DWORD)codebegin + SHELLCODELENTH) - (DWORD)pNewImageBuffer));
	// Ӳ���� = Ҫ��ת��λ��-E9��λ��+5 =Ҫ��ת��λ��-shellcode���λ��

	*(PDWORD)(codebegin + 0xE) = jmpaddr;

	printf("E9:%x\n", *(PDWORD)(codebegin + 0xD));
	printf("ԭOEP:%x\n", pOptionHeader->AddressOfEntryPoint);
	pOptionHeader->AddressOfEntryPoint = codebegin - pNewImageBuffer;
	printf("��OEP:%x\n", pOptionHeader->AddressOfEntryPoint);


	*pNew_ImageBuffer = pNewImageBuffer;
	pNewImageBuffer = NULL;

	return true;
}
/*ѹ������*/
DWORD imageBuffertoNewFileBuffer(LPVOID pNew_ImageBuffer, OUT PVOID* pFileBuffer)
{

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pNew_ImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNew_ImageBuffer + (DWORD)pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(&pNTHeader->OptionalHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	size_t Newsize = pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData + pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData;
	/*printf("sizeof_Newsize:%08x\nNumberOfSections - 1:%u\nPointerToRawData:%08x\n.SizeOfRawData:%08x\n",
		Newsize,
		pPEHeader->NumberOfSections - 1,
		pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData,
		pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData);*/

	LPVOID pNewBuffer = malloc(Newsize);
	if (!pNewBuffer)
	{
		printf(" ����ռ�ʧ��! ");
	}
	else
	{
		memset(pNewBuffer, 0, Newsize);


		memcpy(pNewBuffer, pNew_ImageBuffer, pOptionHeader->SizeOfHeaders);
	}


	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int k = 0; k < pPEHeader->NumberOfSections; k++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pNewBuffer + (DWORD)pTempSectionHeader->PointerToRawData),
			(void*)((DWORD)pNew_ImageBuffer + (DWORD)pTempSectionHeader->VirtualAddress),
			pTempSectionHeader->SizeOfRawData);
	}
	*pFileBuffer = pNewBuffer;
	pNewBuffer = NULL;

	return Newsize;


}
/*����*/
BOOL MemoryToFile(PVOID pFileBuffer, DWORD size, LPSTR lpszFile)
{
	FILE* fp;
	fp = fopen(lpszFile, "wb");
	if (fp != NULL)
	{
		fwrite(pFileBuffer, size, 1, fp);
	}
	fclose(fp);
	return 1;
}
/*�ƶ�������*/
void MoveExportTable(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer)
{
	IniPefileDate(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pPEHeader->NumberOfSections - 1 + pSectionHeader;
	printf("���һ�ڵ����ƣ�%s\n", pLastSectionHeader->Name);
	//pLastSectionHeader->PointerToRawData;
	IMAGE_DATA_DIRECTORY pDatadirectory = pOptionHeader->DataDirectory[0];
	if (pDatadirectory.VirtualAddress == 0)
	{
		printf("û�е�����");
		exit(0);
	}
	PIMAGE_EXPORT_DIRECTORY pEntryExporte = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, pDatadirectory.VirtualAddress));
	/*
	�ڶ���������AddressOfFunctions
	���ȣ�4*NumberOfFunctions
	*/
	PDWORD FuncAddr = (PDWORD)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, pEntryExporte->AddressOfFunctions));
	DWORD sizeofFunc = pEntryExporte->NumberOfFunctions * 4;
	PDWORD CopyFirstAddr = (PDWORD)(pLastSectionHeader->PointerToRawData + (DWORD)pFileBuffer);
	PDWORD functionnewaddr = CopyFirstAddr;
	memcpy(functionnewaddr, FuncAddr, sizeofFunc);
	/*
	������������AddressOfNameOrdinals
	���ȣ�NumberOfNames*2
	*/
	PWORD OrdAddr = (PWORD)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, pEntryExporte->AddressOfNameOrdinals));
	for (size_t i = 0; i < pEntryExporte->NumberOfNames; i++)
	{
		printf("%04X ", OrdAddr[i]);
	}
	printf("\n");
	DWORD sizeofOrd = pEntryExporte->NumberOfNames * 2;
	PDWORD Ordinalnewaddr = (PDWORD)((DWORD)CopyFirstAddr + pEntryExporte->NumberOfFunctions * 4);
	memcpy(Ordinalnewaddr, OrdAddr, sizeofOrd);
	/*
	���Ĳ�������AddressOfNames

	���ȣ�NumberOfNames*4
	*/
	PDWORD NameAddr = (PDWORD)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, pEntryExporte->AddressOfNames));
	PDWORD NamenewAddr = (PDWORD)((DWORD)CopyFirstAddr + pEntryExporte->NumberOfFunctions * 4 + pEntryExporte->NumberOfNames * 2);
	for (size_t i = 0; i < pEntryExporte->NumberOfNames; i++)
	{
		printf("%08X ", NameAddr[i]);
	}
	DWORD sizeofNameAddr = pEntryExporte->NumberOfNames * 4;
	memcpy(NamenewAddr, NameAddr, sizeofNameAddr);

	/*
	���岽���������еĺ�����

	���Ȳ�ȷ��������ʱֱ���޸�AddressOfNames
	*/
	CopyFirstAddr = (PDWORD)((DWORD)CopyFirstAddr + pEntryExporte->NumberOfFunctions * 4 + pEntryExporte->NumberOfNames * 2 + pEntryExporte->NumberOfNames * 4);
	PDWORD RVA_NameAddr = CopyFirstAddr;

	for (DWORD i = 0; i < pEntryExporte->NumberOfNames; i++) {
		char* nameStr = (char*)(RVAToFOA(pFileBuffer, *(DWORD*)NameAddr) + (DWORD)pFileBuffer);
		printf("nameStr = %s\n", nameStr);
		memcpy((PDWORD)(CopyFirstAddr), nameStr, strlen(nameStr) + 1);//�ַ�����β��\0�����˸���
		RVA_NameAddr = (PDWORD)FOAToVA(pFileBuffer, (DWORD)(CopyFirstAddr - (DWORD)pFileBuffer));//�޸Ķ�Ӧ�ĺ������Ʊ��еĵ�ֵַ
		CopyFirstAddr = (PDWORD)((DWORD)CopyFirstAddr + (strlen(nameStr) + 1));
		NameAddr = (PDWORD)((DWORD*)NameAddr + 1);
		RVA_NameAddr++;
	}
	memcpy(CopyFirstAddr, pEntryExporte, sizeof(IMAGE_EXPORT_DIRECTORY));
	//FOAToVA((DWORD)pExporFunctionsAddr , pFileBuffer);
	pEntryExporte->AddressOfFunctions = FOAToVA(pFileBuffer,(DWORD)functionnewaddr - (DWORD)pFileBuffer);
	pEntryExporte->AddressOfNames = FOAToVA(pFileBuffer, (DWORD)NamenewAddr - (DWORD)pFileBuffer);
	pEntryExporte->AddressOfNameOrdinals = FOAToVA( pFileBuffer, (DWORD)Ordinalnewaddr - (DWORD)pFileBuffer);
	pOptionHeader->DataDirectory[0].VirtualAddress = FOAToVA( pFileBuffer, (DWORD)CopyFirstAddr - (DWORD)pFileBuffer);


	memset(pEntryExporte, 0, sizeof(IMAGE_EXPORT_DIRECTORY));

	*pNewFileBuffer = pFileBuffer;
	pFileBuffer = NULL;
}
void MoveRelocTable(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer)
{
	IniPefileDate(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pPEHeader->NumberOfSections - 1 + pSectionHeader;
	printf("���һ�ڵ����ƣ�%s\n", pLastSectionHeader->Name);
	PIMAGE_BASE_RELOCATION Reloction = (PIMAGE_BASE_RELOCATION)(RVAToFOA(pFileBuffer, (pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)) + (DWORD)pFileBuffer);
	printf("Reloction:%08X\n", Reloction);
	int size_of_all = 0;
	while (Reloction->SizeOfBlock && Reloction->VirtualAddress)
	{
		int num_of_items = (Reloction->SizeOfBlock - 8) / 2;
		PWORD pdata = (PWORD)Reloction + 1;
		printf("VirtualAddress:%08X   SizeOfBlock:%08X\n", Reloction->VirtualAddress, Reloction->SizeOfBlock);
		size_of_all = size_of_all + Reloction->SizeOfBlock;

		Reloction = (PIMAGE_BASE_RELOCATION)((DWORD)Reloction + Reloction->SizeOfBlock);
	}

	PDWORD CopyFirstAddr = (PDWORD)(pLastSectionHeader->PointerToRawData + (DWORD)pFileBuffer);
	printf("CopyFirstAddr = %08X Reloction = %08X size_of_all = %08X\n", CopyFirstAddr, Reloction, size_of_all);
	Reloction = (PIMAGE_BASE_RELOCATION)(RVAToFOA(pFileBuffer, (pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)) + (DWORD)pFileBuffer);
	printf("CopyFirstAddr = %08X Reloction = %08X size_of_all = %08X\n", CopyFirstAddr, Reloction, size_of_all);
	memcpy(CopyFirstAddr, Reloction, size_of_all);
	pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = FOAToVA(pFileBuffer,(DWORD)CopyFirstAddr - (DWORD)pFileBuffer);
	*pNewFileBuffer = pFileBuffer;
	pFileBuffer = NULL;
}
DWORD RVAToFOA(LPVOID pFileBuffer, size_t RVA)
{
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + (DWORD)pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(&pNTHeader->OptionalHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	size_t FOA = 0;
	if (RVA < pSectionHeader->VirtualAddress)//�ж�RVA�Ƿ���PEͷ��
	{
		if (RVA < pSectionHeader->PointerToRawData)
			return RVA;//��ʱFOA == RVA
		else
			return 0;
	}

	for (int i = 0; i < pPEHeader->NumberOfSections; i++)//ѭ�������ڱ�ͷ
	{
		if (i)//�����ڱ�ͷ����һ�β�������
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);

		if (RVA >= pSectionHeader->VirtualAddress)//�Ƿ��������ڱ��RVA
		{
			if (RVA <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)//�ж��Ƿ����������
				return (RVA - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;//ȷ�������󣬼���FOA
		}
		else//RVA�����ܴ�ʱ��pSectionHeader->VirtuallAddressС�������Ƿ���ֵΪ0�������
			return 0;
	}

}
DWORD FOAToVA(LPVOID pFileBuffer, size_t FOA) {
	IniPefileDate(pFileBuffer);
	if (FOA < pSectionHeader->PointerToRawData) {
		return FOA + (DWORD)pFileBuffer;
	}
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++) {
		if (FOA >= pSectionHeader->PointerToRawData && FOA < (pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)) {
			return pSectionHeader->VirtualAddress + (FOA - pSectionHeader->PointerToRawData);
		}
		pSectionHeader++;
	}
	return 0;
}
void IniPefileDate(LPVOID pFileBuffer)
{
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + (DWORD)pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(&pNTHeader->OptionalHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + (DWORD)pPEHeader->SizeOfOptionalHeader);
}
void PrintInfo(LPVOID pFileBuffer)
{
	IniPefileDate(pFileBuffer);
	printf("================PE_Table================\n");
	printf("NTͷ = %X\nPE��־ = %X\n�ڱ�ĸ��� = %d\n��ѡͷ��С = %08X\nEOA = %08X\nImageBase =  %08X\n�ļ����� =  %X\n�ڴ���� =  %X\nPEͷ��С = %08X\n,Image��С = %08X\n",
		pDosHeader->e_lfanew,
		pNTHeader->Signature,
		pPEHeader->NumberOfSections,
		pPEHeader->SizeOfOptionalHeader,
		pOptionHeader->AddressOfEntryPoint,
		pOptionHeader->ImageBase,
		pOptionHeader->FileAlignment,
		pOptionHeader->SectionAlignment,
		pOptionHeader->SizeOfHeaders,
		pOptionHeader->SizeOfImage);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + (DWORD)pPEHeader->SizeOfOptionalHeader + IMAGE_SIZEOF_SECTION_HEADER * i);
		printf("�ڱ��� = %s\tPToRData = %08X SizeOfRData = %08X VA = %08X VSize = %08X ���� = %08X\n", pSectionHeader->Name, pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize,pSectionHeader->Characteristics);
	}
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + (DWORD)pPEHeader->SizeOfOptionalHeader);
	printf("================Data_Directory================\n");
	PEtables = pOptionHeader->DataDirectory[0];

	Exportable = (PIMAGE_EXPORT_DIRECTORY)RVAToFOA(pFileBuffer, PEtables.VirtualAddress); //ָ�򵼳���//RVAתFOA

	printf("pFileBuffer��ַ:%08X\n", pFileBuffer);

	printf("������FOA:%08X\nSize = %X\n", Exportable, PEtables.Size);
	TrueExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + (DWORD)Exportable);
	printf("�������ַΪ:%08X\n================Export_Directory================\n", TrueExport);

	//printf("AddressOfNames = %08X\nTrueAddressOfNames = %08X\nFOA_AddressOfNames = %08X\nFOA_TrueAddressOfNames = %08X\nTrueExport->NumberOfNames = %d\nAddressOfFunctions = %08X\nTrueAddressOfFunctions = %08X\nTrueNumberOfFunctions = %d\nAddressOfNameOrdinals = %08X\nTrueAddressOfNameOrdinals = %08X\nTrueExport->Name-->Address = %08X FOA_Address = %08X -->%s\nTrueExport->Base = %08X\n",
	//	TrueExport->AddressOfNames,
	//	(DWORD)pFileBuffer + TrueExport->AddressOfNames,
	//	RVAToFOA(pFileBuffer, TrueExport->AddressOfNames),
	//	(DWORD)pFileBuffer + RVAToFOA(pFileBuffer, TrueExport->AddressOfNames),
	//	TrueExport->NumberOfNames, //5
	//	TrueExport->AddressOfFunctions,
	//	(DWORD)pFileBuffer + TrueExport->AddressOfFunctions,
	//	TrueExport->NumberOfFunctions,
	//	TrueExport->AddressOfNameOrdinals,
	//	(DWORD)pFileBuffer + TrueExport->AddressOfNameOrdinals,
	//	TrueExport->Name,
	//	(DWORD)pFileBuffer + TrueExport->Name,
	//	(DWORD)pFileBuffer + TrueExport->Name,
	//	TrueExport->Base);
	DWORD* FOA_Name = (DWORD*)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, TrueExport->AddressOfNames));
	/*
	Exportable = RVAToFOA(PEtables[0].VirtualAddress)���������ݵĵ�ַ
	TrueExport = pFileBuffer+ RVAToFOA(Exportable) ���������ݵ���ʵ��ַ
	nametable_addr=RVAToFOA(TrueExport.AddressOfNames) �����������������������ĵ�ַ
	nametable_addr_True = pFileBuffer+ RVAToFOA(TrueExport.AddressOfNames) �����������������������ĵ�ַ
	name_addr = RVAToFOA(name_addr+i)���������������������ĵ�ַ
	name = pFileBuffer+RVAToFOA(name_addr+i)������������������������ʵ��ַ������Ҫ��ȡ���ֵĵ�ַ��
	*/

	printf("\n================FunctionNameTable================\n");
	for (size_t k = 0; k < TrueExport->NumberOfNames; k++) {
		printf("FOA_Name = %08X --> %s\n", *(FOA_Name + k), (char*)(RVAToFOA(pFileBuffer, *(FOA_Name + k)) + (DWORD)pFileBuffer));
		//Name��ַ����filebuffer�����Ƕ�ȡNameֵ����Ҫ��FileBuffer��
	}
	printf("\n================FunctionOrdinalsTable================\n");
	WORD* Ordinals = (WORD*)((DWORD)pFileBuffer + RVAToFOA(pFileBuffer, TrueExport->AddressOfNameOrdinals));
	/*	Ordinals_addr = RVAToFOA(TrueExport->AddressOfNameOrdinals)
	Ordinals_addr_True = pFileBuffer + RVAToFOA(TrueExport->AddressOfNameOrdinals)*/
	for (size_t i = 0; i < TrueExport->NumberOfNames; i++)
	{
		printf("Ordinals = %04X\n", Ordinals[i] + TrueExport->Base);
		printf("Ordinals-Base = %04X\n", Ordinals[i]);
	}
	printf("================FunctionAddressTable================\n");
	DWORD* functions = (DWORD*)(RVAToFOA(pFileBuffer, TrueExport->AddressOfFunctions) + (DWORD)pFileBuffer);
	/*
	functionstable_addr = RVAToFOA(TrueExport->AddressOfFunctions)
	functionstable_addr_True = pFileBuffer + RVAToFOA(TrueExport->AddressOfFunctions)
	*/
	for (size_t i = 0; i < TrueExport->NumberOfFunctions; i++)
	{
		printf("FOA_functions = %08X\n", *(functions + i)); 
		//functions[Ordinals[i]] ��������� ��Ϊ����˳���������ͺ���������һ�£�demotll2.dll ����������5�� ����˳���ֻ��3�� ���Զ�ȡ����һЩ�ڴ�
	}
	PDWORD Name_True_Addr = NULL;
	printf("================FunctionByNames================\n");
	for (size_t i = 0; i < TrueExport->NumberOfNames; i++)
	{
		Name_True_Addr = (PDWORD)(FOA_Name[i] + (DWORD)pFileBuffer);
		printf("Name_addr:%08X-->%s\n", Name_True_Addr, Name_True_Addr);
		printf("Ordinals = %04X\n", Ordinals[i] + TrueExport->Base);
		//DWORD Functions_num[i*(Ordinals + i) + 1] = 0;
		printf("FOA_functions = %08X\n", functions[Ordinals[i]]);
	}
	printf("================Reloctiontable================\n");
	Reloctiontable = (PIMAGE_BASE_RELOCATION)(RVAToFOA(pFileBuffer, (pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)));
	TrueReloc = (PIMAGE_BASE_RELOCATION)((DWORD)Reloctiontable + (DWORD)pFileBuffer);
	printf("Reloctiontable = %08X\nTrueReloc = %08X\nSize = %X\n", Reloctiontable, TrueReloc, pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	int size_of_all = 0;
	while (TrueReloc->SizeOfBlock && TrueReloc->VirtualAddress)
	{
		int num_of_items = (TrueReloc->SizeOfBlock - 8) / 2;
		PWORD pdata = (PWORD)TrueReloc + 1;
		printf("================ReloctionItem================\n");
		printf("VirtualAddress:%08X   SizeOfBlock:%08X\n", TrueReloc->VirtualAddress, TrueReloc->SizeOfBlock);
		for (int i = 0; i < num_of_items; i++, pdata++)
		{
			if ((0xf000 & (*pdata)) >> 12 == 3)
			{
				printf("type:%02x RVA:%08X\n", (0xf000 & (*pdata)) >> 12, (0x0fff & (*pdata)) + TrueReloc->VirtualAddress);

			}
		}
		size_of_all = size_of_all + TrueReloc->SizeOfBlock;
		printf("size_of_all = %08X\n", size_of_all);
		TrueReloc = (PIMAGE_BASE_RELOCATION)((DWORD)TrueReloc + TrueReloc->SizeOfBlock);
	}
}
VOID operate()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pNewFileBuffer = NULL;
	LPVOID pSaveFileBuffer = NULL;
	LPVOID FileBuffer = NULL;
	DWORD ret1 = ReadPEFile(file_path, &pFileBuffer);  // &pFileBuffer(void**����) ���ݵ�ַ����ֵ���Խ����޸�
	printf("\nexe->filebuffer  Ϊ���������ļ���С��%08x\n", ret1);
	DWORD ret2 = AddFileBuffer(pFileBuffer, ret1, &pNewFileBuffer);
	printf("\nfilebuffer->Newfilebuffer  Ϊ���������ļ���С��%08x\n", ret2);
	ChangePEinfo(pNewFileBuffer,&pSaveFileBuffer);
	//MoveExportTable(pSaveFileBuffer, &FileBuffer);
	MoveRelocTable(pSaveFileBuffer, &FileBuffer);
	PrintInfo(FileBuffer);
	MemoryToFile(FileBuffer, ret2, write_file_path);
	free(pFileBuffer); 
	free(pNewFileBuffer);
	//free(pSaveFileBuffer);
}
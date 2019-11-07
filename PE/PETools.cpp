#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "PETools.h"

PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer) {
	return (PIMAGE_DOS_HEADER)pFileBuffer;
}

PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer) {
	return (PIMAGE_NT_HEADERS)((size_t)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew);
}

PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer) {
	return (PIMAGE_FILE_HEADER)((size_t)getNTHeader(pFileBuffer) + 4);
}

PIMAGE_OPTIONAL_HEADER32 getOptionalHeader32(void* pFileBuffer) {
	return (PIMAGE_OPTIONAL_HEADER32)((size_t)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
}

PIMAGE_SECTION_HEADER getFirstSectionHeader(void* pFileBuffer) {
	return (PIMAGE_SECTION_HEADER)((size_t)getOptionalHeader32(pFileBuffer) + getFileHeader(pFileBuffer)->SizeOfOptionalHeader);
}

size_t faToRva(void* pFileBuffer, size_t fa) {
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	size_t foa = fa - (size_t)pFileBuffer;

	// PEͷ�ڲ�
	if (foa < pOptionalHeader32->SizeOfHeaders) {
		return foa;
	}

	// PE�������ڲ�
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (foa >= pFirstSectionHeader->PointerToRawData && foa < pFirstSectionHeader->PointerToRawData + pFirstSectionHeader->SizeOfRawData) {
			return foa - pFirstSectionHeader->PointerToRawData + pFirstSectionHeader->VirtualAddress;
		}
		pFirstSectionHeader++;
	}

	printf("faת��ʧ��\n");
	return 0;
}

void* rvaToFa(void* pFileBuffer, size_t rva) {
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// PEͷ�ڲ�
	if (rva < pOptionalHeader32->SizeOfHeaders) {
		return (void*)((size_t)pFileBuffer + rva);
	}

	// PE�������ڲ�
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (rva >= pFirstSectionHeader->VirtualAddress && rva < pFirstSectionHeader->VirtualAddress + pFirstSectionHeader->SizeOfRawData) {
			return (void*)((size_t)pFileBuffer + rva - pFirstSectionHeader->VirtualAddress + pFirstSectionHeader->PointerToRawData);
		}
		pFirstSectionHeader++;
	}

	printf("rvaת��ʧ��\n");
	return NULL;
}

// ��ȡ��Ӧ���ݱ����ʼfa
void* getDataDirectory(void* pFileBuffer, size_t index) {
	size_t dataDirectoryRva = getOptionalHeader32(pFileBuffer)->DataDirectory[index].VirtualAddress;
	return dataDirectoryRva ? rvaToFa(pFileBuffer, dataDirectoryRva) : NULL;
}

// �����µ��ļ���
char* createNewFilePath(const char* pOldFilePath, const char* addedStr) {
	size_t size = strlen(pOldFilePath) + 20;
	char* pNewFilePath = (char*)malloc(size);
	if (!pNewFilePath) {
		printf("�����ڴ�ʧ��\n");
		return NULL;
	}
	memset(pNewFilePath, 0, size);

	strcpy_s(pNewFilePath, size, pOldFilePath);
	char* dest = strrchr(pNewFilePath, '.');
	char ext[10];
	strcpy_s(ext, 10, dest);
	*dest = 0;
	strcat_s(pNewFilePath, size, "-");
	strcat_s(pNewFilePath, size, addedStr);
	strcat_s(pNewFilePath, size, ext);
	return pNewFilePath;
}

// �������϶���
size_t dataAlign(size_t data, size_t base) {
	return (data / base + 1) * base;
}


size_t readPEFile(const char* pFilePath, void** ppFileBuffer) {
	FILE* pFile = NULL;
	size_t fileSize = 0;

	// ���ļ�
	fopen_s(&pFile, pFilePath, "rb");
	if (!pFile) {
		printf("���ļ�ʧ��\n");
		return 0;
	}

	// ��ȡ�ļ���С
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// �����ļ�������
	*ppFileBuffer = malloc(fileSize);
	if (!*ppFileBuffer) {
		printf("�����ڴ�ʧ��\n");
		fclose(pFile);
		return 0;
	}
	memset(*ppFileBuffer, 0, fileSize);

	//��ȡ�ļ���������
	size_t n = fread(*ppFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf("��ȡ�ļ���������ʧ��\n");
		free(*ppFileBuffer);
		*ppFileBuffer = NULL;
		fclose(pFile);
		return 0;
	}

	// �ر��ļ�
	fclose(pFile);

	return fileSize;
}

void printPEHeader(const char* pFilePath) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionHeader64 = NULL;
	PIMAGE_SECTION_HEADER pFirstSectionHeader = NULL;

	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	// �ж�MZ���
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {
		printf("û��MZ���, ����PE�ļ�\n");
		free(pFileBuffer);
		return;
	}

	// DosHeader
	pDosHeader = getDosHeader(pFileBuffer);
	printf("******************** DosHeader ********************\n");
	printf("e_magic: %X\n", pDosHeader->e_magic);
	printf("e_lfanew: %X\n", pDosHeader->e_lfanew);

	// �ж�PE���
	if (*((size_t*)((size_t)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		printf("û��PE���\n");
		free(pFileBuffer);
		return;
	}

	// NTHeader
	pNTHeader = getNTHeader(pFileBuffer);
	printf("\n******************** NTHeader ********************\n");
	printf("NT: %X\n", pNTHeader->Signature);
	// FileHeader
	pPEHeader = getFileHeader(pFileBuffer);
	printf("\n******************** FileHeader ********************\n");
	printf("Machine: %X\n", pPEHeader->Machine);
	printf("NumberOfSections: %X\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader: %X\n", pPEHeader->SizeOfOptionalHeader);
	// OptionalHeader
	pOptionHeader32 = getOptionalHeader32(pFileBuffer);
	printf("\n******************** OptionalHeader ********************\n");
	printf("Magic: %X\n", pOptionHeader32->Magic);
	printf("AddressOfEntryPoint: %X\n", pOptionHeader32->AddressOfEntryPoint);
	printf("ImageBase: %X\n", pOptionHeader32->ImageBase);
	printf("SectionAlignment: %X\n", pOptionHeader32->SectionAlignment);
	printf("FileAlignment: %X\n", pOptionHeader32->FileAlignment);
	printf("SizeOfImage: %X\n", pOptionHeader32->SizeOfImage);
	printf("SizeOfHeaders: %X\n", pOptionHeader32->SizeOfHeaders);

	// SectionHeader
	printf("\n******************** SectionHeader ********************\n");
	pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++) {
		// �������ȿ���Ϊ8
		unsigned char name[9];
		for (size_t i = 0; i < 8; i++) {
			name[i] = pFirstSectionHeader->Name[i];
		}
		name[8] = 0;
		printf("Name: %s\n", name);
		printf("Misc: %X\n", pFirstSectionHeader->Misc.VirtualSize);
		printf("VirtualAddress: %X\n", pFirstSectionHeader->VirtualAddress);
		printf("SizeOfRawData: %X\n", pFirstSectionHeader->SizeOfRawData);
		printf("PointerToRawData: %X\n", pFirstSectionHeader->PointerToRawData);
		printf("Characteristics: %X\n\n", pFirstSectionHeader->Characteristics);

		pFirstSectionHeader++;
	}
}

size_t copyFileBufferToImageBuffer(void* pFileBuffer, void** ppImageBuffer) {
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// �����ڴ�
	size_t sizeOfImage = pOptionalHeader32->SizeOfImage;
	*ppImageBuffer = malloc(sizeOfImage);
	if (!*ppImageBuffer) {
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(*ppImageBuffer, 0, sizeOfImage);

	// ����ͷ��
	size_t sizeOfHeaders = pOptionalHeader32->SizeOfHeaders;
	memcpy(*ppImageBuffer, pFileBuffer, sizeOfHeaders);

	// ���Ƹ�����
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		void* dst = (void*)((size_t)*ppImageBuffer + pFirstSectionHeader->VirtualAddress);
		void* src = (void*)((size_t)pFileBuffer + pFirstSectionHeader->PointerToRawData);
		size_t size = pFirstSectionHeader->SizeOfRawData;
		memcpy(dst, src, size);
		pFirstSectionHeader++;
	}

	return sizeOfImage;
}

size_t copyImageBufferToNewBuffer(void* pImageBuffer, void** ppNewBuffer) {
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pImageBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pImageBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pImageBuffer);

	size_t offset = IMAGE_SIZEOF_SECTION_HEADER * (pFileHeader->NumberOfSections - 1);
	pFirstSectionHeader = (PIMAGE_SECTION_HEADER)((size_t)pFirstSectionHeader + offset);
	size_t sizeOfFile = pFirstSectionHeader->PointerToRawData + pFirstSectionHeader->SizeOfRawData;
	pFirstSectionHeader = getFirstSectionHeader(pImageBuffer);

	// �����ڴ�
	*ppNewBuffer = malloc(sizeOfFile);
	if (!*ppNewBuffer) {
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(*ppNewBuffer, 0, sizeOfFile);

	// ����ͷ��
	size_t sizeOfHeaders = pOptionalHeader32->SizeOfHeaders;
	memcpy(*ppNewBuffer, pImageBuffer, sizeOfHeaders);

	// ���Ƹ�����
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		void* dst = (void*)((size_t)*ppNewBuffer + pFirstSectionHeader->PointerToRawData);
		void* src = (void*)((size_t)pImageBuffer + pFirstSectionHeader->VirtualAddress);
		size_t size = pFirstSectionHeader->SizeOfRawData;
		memcpy(dst, src, size);
		pFirstSectionHeader++;
	}

	return sizeOfFile;
}

size_t writeFileBufferToFile(const char* pFilePath, const void* pFileBuffer, size_t fileSize) {
	FILE* pFile = NULL;
	fopen_s(&pFile, pFilePath, "wb+");
	if (!pFile) {
		printf("�ļ�����ʧ��\n");
		return 0;
	}

	size_t n = fwrite(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf("�ļ�д��ʧ��\n");
		fclose(pFile);
		return 0;
	}

	fclose(pFile);
	return fileSize;
}

void injectShellCode(const char* pFilePath, size_t sectionNum) {
	size_t MESSAGE_BOX_ADDR = 0x77D507EA;
	size_t SHELL_CODE_LEN = 18;
	char SHELL_CODE[] = {
		0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,		// 4 * PUSH 0
		0xe8, 0x00, 0x00, 0x00, 0x00,						// CALL 
		0xe9, 0x00, 0x00, 0x00, 0x00						// JMP
	};

	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	// ����
	void* pImageBuffer = NULL;
	copyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		free(pFileBuffer);
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pImageBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pImageBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pImageBuffer);
	size_t textCharacteristics = pFirstSectionHeader->Characteristics;
	pFirstSectionHeader += sectionNum;
	// �ж��Ƿ����㹻�Ŀռ�
	if (pFirstSectionHeader->SizeOfRawData <= pFirstSectionHeader->Misc.VirtualSize
		|| pFirstSectionHeader->SizeOfRawData - pFirstSectionHeader->Misc.VirtualSize < SHELL_CODE_LEN) {
		printf("�ռ䲻��\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	// ����shellCode
	unsigned char* shellCodeStart = (unsigned char*)
		((size_t)pImageBuffer + (pFirstSectionHeader->VirtualAddress + pFirstSectionHeader->Misc.VirtualSize));
	memcpy(shellCodeStart, SHELL_CODE, SHELL_CODE_LEN);
	// �����ַ
	size_t callAddr = MESSAGE_BOX_ADDR - ((size_t)shellCodeStart - (size_t)pImageBuffer + 13 + pOptionalHeader32->ImageBase);
	size_t jmpAddr = pOptionalHeader32->AddressOfEntryPoint - ((size_t)shellCodeStart - (size_t)pImageBuffer + 18);
	*(size_t*)(shellCodeStart + 9) = callAddr;
	*(size_t*)(shellCodeStart + 14) = jmpAddr;
	// ������ڵ�ַ
	pOptionalHeader32->AddressOfEntryPoint = (size_t)shellCodeStart - (size_t)pImageBuffer;
	// ���Ľ�����
	pFirstSectionHeader->Characteristics |= textCharacteristics;

	// ѹ��
	void* pNewBuffer = NULL;
	size_t fileSize = copyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (!pNewBuffer) {
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	// ����
	char* newFilePath = createNewFilePath(pFilePath, "����ע��");
	if (!newFilePath) {
		free(pFileBuffer);
		free(pImageBuffer);
		free(pNewBuffer);
		return;
	}
	writeFileBufferToFile(newFilePath, pNewBuffer, fileSize);

	// �ͷ��ڴ�
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	free(newFilePath);
}

size_t addSection(const char* pFilePath, void** ppNewFileBuffer, size_t addSectionSize) {
	char ADD_SECTION_NAME[8] = ".new";

	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return 0;
	}

	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_NT_HEADERS pNTHeaders = getNTHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections;

	// ȥ��Dosͷ�������������
	size_t movedSize = (size_t)pNewSectionHeader - (size_t)pNTHeaders;
	memcpy((void*)((size_t)pFileBuffer + 0x40), (void*)pNTHeaders, movedSize);
	memset((void*)((size_t)pFileBuffer + 0x40 + movedSize), 0, (size_t)pNTHeaders - ((size_t)pFileBuffer + 0x40));
	pDosHeader->e_lfanew = 0x40;

	pFileHeader = getFileHeader(pFileBuffer);
	pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	pLastSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections - 1;
	pNewSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections;

	// �ж��Ƿ����㹻�Ŀռ�
	if (pOptionalHeader32->SizeOfHeaders - ((size_t)pNewSectionHeader - (size_t)pFileBuffer) < 80) {
		printf("�ռ䲻��\n");
		free(pFileBuffer);
		return 0;
	}

	// ����½�
	memset(pNewSectionHeader, 0, 80);
	pFileHeader->NumberOfSections++;
	pOptionalHeader32->SizeOfImage = dataAlign(pOptionalHeader32->SizeOfImage, 0x1000) + addSectionSize;
	memcpy(pNewSectionHeader->Name, ADD_SECTION_NAME, 8);
	pNewSectionHeader->Misc.VirtualSize = addSectionSize;
	pNewSectionHeader->VirtualAddress = pOptionalHeader32->SizeOfImage - addSectionSize;
	pNewSectionHeader->SizeOfRawData = addSectionSize;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	// �������нڵ�����
	size_t mergeCharacteristics = 0;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		mergeCharacteristics |= (pFirstSectionHeader + i)->Characteristics;
	}
	pNewSectionHeader->Characteristics = mergeCharacteristics;

	// ���Ƶ��µ��ļ�������
	size_t newSize = pNewSectionHeader->PointerToRawData + pNewSectionHeader->SizeOfRawData;
	void* pNewFileBuffer = NULL;
	pNewFileBuffer = malloc(newSize);
	if (!pNewFileBuffer) {
		free(pFileBuffer);
		return 0;
	}
	memset(pNewFileBuffer, 0, newSize);
	memcpy(pNewFileBuffer, pFileBuffer, newSize - addSectionSize);
	*ppNewFileBuffer = pNewFileBuffer;

	// ����
	char* pNewFilePath = createNewFilePath(pFilePath, "���ӽ�");
	if (!pNewFilePath) {
		free(pFileBuffer);
		return newSize;
	}
	//writeFileBufferToFile(pNewFilePath, pNewFileBuffer, newSize);

	free(pFileBuffer);
	free(pNewFilePath);

	return newSize;
}

void expandLastSection(const char* pFilePath) {
	size_t EXPAND_SIZE = 0x1000;

	// ���ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pFirstSectionHeader + pFileHeader->NumberOfSections - 1;

	// �޸����ڵ�����
	pOptionalHeader32->SizeOfImage += EXPAND_SIZE;
	pLastSectionHeader->Misc.VirtualSize += EXPAND_SIZE;
	pLastSectionHeader->SizeOfRawData += EXPAND_SIZE;

	// ���Ƶ��µĻ�����
	size_t newSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	void* pNewFileBuffer = NULL;
	pNewFileBuffer = malloc(newSize);
	if (!pNewFileBuffer) {
		free(pFileBuffer);
		return;
	}
	memset(pNewFileBuffer, 0, newSize);
	memcpy(pNewFileBuffer, pFileBuffer, newSize - EXPAND_SIZE);

	// ����
	char* pNewFilePath = createNewFilePath(pFilePath, "�����");
	if (!pNewFilePath) {
		free(pFileBuffer);
		free(pNewFileBuffer);
		return;
	}
	writeFileBufferToFile(pNewFilePath, pNewFileBuffer, newSize);

	free(pNewFilePath);
	free(pFileBuffer);
	free(pNewFileBuffer);
}

void MergeSections(const char* pFilePath) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	// ����
	void* pImageBuffer = NULL;
	copyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer) {
		free(pFileBuffer);
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pImageBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader32(pImageBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pImageBuffer);

	// �޸Ľ�����
	size_t mergeCharacteristics = 0;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		mergeCharacteristics |= (pFirstSectionHeader + i)->Characteristics;
	}
	size_t newSectionSize = pOptionalHeader->SizeOfImage - pFirstSectionHeader->VirtualAddress;
	pFileHeader->NumberOfSections = 1;
	pFirstSectionHeader->Misc.VirtualSize = newSectionSize;
	pFirstSectionHeader->SizeOfRawData = newSectionSize;
	pFirstSectionHeader->Characteristics = mergeCharacteristics;
	pFirstSectionHeader->PointerToRawData = pFirstSectionHeader->VirtualAddress;
	memset((void*)(pFirstSectionHeader + 1), 0, 40);

	// ����
	char* pNewFilePath = createNewFilePath(pFilePath, "�ϲ���");
	if (!pNewFilePath) {
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	writeFileBufferToFile(pNewFilePath, pImageBuffer, pOptionalHeader->SizeOfImage);

	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewFilePath);
}

void printDataDirectory(const char* pFilePath) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader32(pFileBuffer);

	for (size_t i = 0; i < pOptionalHeader->NumberOfRvaAndSizes; i++) {
		IMAGE_DATA_DIRECTORY directory = pOptionalHeader->DataDirectory[i];
		printf("VirtualAddress: %X Size: %X\n", directory.VirtualAddress, directory.Size);
	}

	free(pFileBuffer);
}

void printExportDirectory(const char* pFilePath) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)getDataDirectory(pFileBuffer, 0);
	if (!pExportDirectory) {
		printf("û�е�����\n");
		free(pFileBuffer);
		return;
	}

	printf("Name: %s\n", (char*)(rvaToFa(pFileBuffer, pExportDirectory->Name)));
	printf("Base: %08x\n", pExportDirectory->Base);
	printf("NumberOfFunctions: %08x\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames: %08x\n", pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions: %08x\n", pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames: %08x\n", pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals: %08x\n", pExportDirectory->AddressOfNameOrdinals);

	printf("\nFunction Table\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
		printf("Rva%d: %08x\n", i, *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfFunctions) + i));
	}

	printf("\nName Table\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		size_t rva = *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNames) + i);
		printf("Name%d: %s\n", i, (char*)rvaToFa(pFileBuffer, rva));
	}

	printf("\nNameOrdinal Table\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		printf("NameOrdinal%d: %x\n", i, *((short*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals) + i));
	}

	free(pFileBuffer);
}

size_t GetFunctionAddrByName(const char* pFilePath, const char* funName) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return 0;
	}

	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)getDataDirectory(pFileBuffer, 0);
	if (!pExportDirectory) {
		printf("û�е�����\n");
		free(pFileBuffer);
		return 0;
	}

	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		size_t nameRva = *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNames) + i);
		if (!strcmp(funName, (char*)rvaToFa(pFileBuffer, nameRva))) {
			size_t nameOrdinal = *((short*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals) + i);
			size_t funAddr = pOptionalHeader32->ImageBase
				+ *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfFunctions) + nameOrdinal);
			free(pFileBuffer);
			return funAddr;
		}
	}

	free(pFileBuffer);
	return 0;
}

size_t GetFunctionAddrByOrdinal(const char* pFilePath, size_t funOrdinal) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return 0;
	}

	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)getDataDirectory(pFileBuffer, 0);
	if (!pExportDirectory) {
		printf("û�е�����\n");
		free(pFileBuffer);
		return 0;
	}

	funOrdinal -= pExportDirectory->Base;
	size_t funAddr = 0;
	if (funOrdinal < pExportDirectory->NumberOfFunctions) {
		funAddr = pOptionalHeader32->ImageBase
			+ *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfFunctions) + funOrdinal);
	}

	free(pFileBuffer);
	return funAddr;
}

void printBaseRelocation(const char* pFilePath) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);
	if (!pBaseRelocation) {
		printf("û���ض�λ��\n");
		free(pFileBuffer);
		return;
	}

	while (pBaseRelocation->VirtualAddress) {
		printf("VirtualAddress: %x SizeOfBlock: %x\n", pBaseRelocation->VirtualAddress, pBaseRelocation->SizeOfBlock);
		unsigned short* t = (unsigned short*)((size_t)pBaseRelocation + 8);
		for (size_t i = 0; i < (pBaseRelocation->SizeOfBlock - 8) / 2; i++) {
			size_t rva = (*t) & 0xFFF;
			printf("%d: %x : %x\n", i, rva == 0 ? 0 : rva + pBaseRelocation->VirtualAddress, (*t) >> 12);
			t++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((size_t)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		printf("**********************************\n");
	}

	free(pFileBuffer);
}

void moveExportDirectory(const char* pFilePath) {
	// ���ӽ�
	void* pFileBuffer = NULL;
	size_t fileSize = addSection(pFilePath, &pFileBuffer, 0x1000);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = getFirstSectionHeader(pFileBuffer) + pFileHeader->NumberOfSections - 1;

	// ��ȡExportDirectory
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)getDataDirectory(pFileBuffer, 0);
	if (!pExportDirectory) {
		printf("û�е�����\n");
		free(pFileBuffer);
		return;
	}

	// �µ�������ʼ��
	size_t pStart = (size_t)pFileBuffer + pLastSectionHeader->PointerToRawData;
	// �ƶ�Functions��
	memcpy((void*)pStart, rvaToFa(pFileBuffer, pExportDirectory->AddressOfFunctions), pExportDirectory->NumberOfFunctions * 4);
	pExportDirectory->AddressOfFunctions = faToRva(pFileBuffer, pStart);
	pStart += (pExportDirectory->NumberOfFunctions) * 4;
	// �ƶ�NameOrdinals��
	memcpy((void*)pStart, rvaToFa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals), pExportDirectory->NumberOfNames * 2);
	pExportDirectory->AddressOfNameOrdinals = faToRva(pFileBuffer, pStart);
	pStart += (pExportDirectory->NumberOfNames) * 2;
	// �ƶ�Names��
	memcpy((void*)pStart, rvaToFa(pFileBuffer, pExportDirectory->AddressOfNames), pExportDirectory->NumberOfNames * 4);
	pExportDirectory->AddressOfNames = faToRva(pFileBuffer, pStart);
	pStart += (pExportDirectory->NumberOfNames) * 4;
	// �ƶ�����Name
	size_t* ppName = (size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNames);
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		char* pName = (char*)rvaToFa(pFileBuffer, *ppName);
		size_t size = strlen(pName) + 1;
		memcpy((void*)pStart, pName, size);
		*ppName = faToRva(pFileBuffer, pStart);

		ppName++;
		pStart += size;
	}
	// �ƶ�������
	memcpy((void*)pStart, pExportDirectory, 40);
	pOptionalHeader32->DataDirectory[0].VirtualAddress = faToRva(pFileBuffer, pStart);

	// �������ļ���
	char* pNewFilePath = createNewFilePath(pFilePath, "�ƶ�������");
	if (!pNewFilePath) {
		free(pFileBuffer);
		printf("����NewFilePathʧ��\n");
		return;
	}
	writeFileBufferToFile(pNewFilePath, pFileBuffer, fileSize);

	free(pFileBuffer);
	free(pNewFilePath);
}

void moveBaseRelocation(const char* pFilePath) {
	// �ӽ�
	void* pFileBuffer = NULL;
	size_t fileSize = addSection(pFilePath, &pFileBuffer, 0x2000);
	if (!pFileBuffer) {
		printf("�ӽ�ʧ��\n");
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = getFirstSectionHeader(pFileBuffer) + pFileHeader->NumberOfSections - 1;

	// ��ȡ�ض�λ��
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);
	if (!pBaseRelocation) {
		printf("û���ض�λ��\n");
		free(pFileBuffer);
		return;
	}

	size_t size = 0;
	while (pBaseRelocation->VirtualAddress) {
		size += pBaseRelocation->SizeOfBlock;
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((size_t)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);

	// �����ض�λ��
	size_t pStart = (size_t)pFileBuffer + pLastSectionHeader->PointerToRawData;
	memcpy((void*)pStart, pBaseRelocation, size);
	pOptionalHeader32->DataDirectory[5].VirtualAddress = faToRva(pFileBuffer, pStart);

	// �������ļ���
	char* pNewFilePath = createNewFilePath(pFilePath, "�ƶ��ض�λ��");
	if (!pNewFilePath) {
		free(pFileBuffer);
		printf("�������ļ���ʧ��\n");
		return;
	}
	writeFileBufferToFile(pNewFilePath, pFileBuffer, fileSize);

	free(pFileBuffer);
	free(pNewFilePath);
}

void modifyImageBase(const char* pFilePath, size_t newImageBase) {
	void* pFileBuffer = NULL;
	size_t fileSize = readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	// ��ȡBaseRelocation
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);
	if (!pBaseRelocation) {
		printf("û���ض�λ��\n");
		free(pFileBuffer);
		return;
	}

	// �޸���Ҫ�ض�λ�ĵ�ַ
	while (pBaseRelocation->VirtualAddress) {
		unsigned short* t = (unsigned short*)((size_t)pBaseRelocation + 8);
		for (size_t i = 0; i < (pBaseRelocation->SizeOfBlock - 8) / 2; i++) {
			size_t rva = (*t) & 0xFFF;
			if (rva && (((*t) >> 12) == 3)) {
				size_t* fa = (size_t*)rvaToFa(pFileBuffer, rva + pBaseRelocation->VirtualAddress);
				*fa = *fa - pOptionalHeader32->ImageBase + newImageBase;
			}
			t++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((size_t)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	// �޸�ImageBase
	pOptionalHeader32->ImageBase = newImageBase;

	// �������ļ���
	char* pNewFilePath = createNewFilePath(pFilePath, "�޸�ImageBase");
	if (!pNewFilePath) {
		free(pFileBuffer);
		printf("�������ļ���ʧ��\n");
		return;
	}
	writeFileBufferToFile(pNewFilePath, pFileBuffer, fileSize);

	free(pFileBuffer);
	free(pNewFilePath);
}

void printImportDirectory(const char* pFilePath) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 1);
	if (!pImportDescriptor) {
		printf("û�е����\n");
		free(pFileBuffer);
		return;
	}

	while (pImportDescriptor->OriginalFirstThunk) {
		printf("Name: %s\n", (char*)rvaToFa(pFileBuffer, pImportDescriptor->Name));
		printf("INT: \n");
		size_t* arr = (size_t*)rvaToFa(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
		while (*arr) {
			// �������
			if ((*arr) & 0x80000000) {
				printf("\t%x\n", (*arr) & 0x7FFFFFFF);
			}
			// ������
			else {
				printf("\t%s\n", ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*arr) & 0x7FFFFFFF))->Name);
			}
			arr++;
		}

		printf("IAT: \n");
		arr = (size_t*)rvaToFa(pFileBuffer, pImportDescriptor->FirstThunk);
		while (*arr) {
			// IATԤ����
			if (pImportDescriptor->TimeDateStamp) {
				printf("\t%x\n", *arr);
			}
			else {
				if ((*arr) & 0x80000000) {
					printf("\t%x\n", (*arr) & 0x7FFFFFFF);
				}
				else {
					printf("\t%s\n", ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*arr) & 0x7FFFFFFF))->Name);
				}
			}
			arr++;
		}
		printf("************************************************\n");
		pImportDescriptor++;
	}

	free(pFileBuffer);
}

void printBoundImportDirectory(const char* pFilePath) {
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDirectory = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 11);
	if (!pBoundImportDirectory) {
		printf("û�а󶨵����\n");
		free(pFileBuffer);
		return;
	}

	PIMAGE_BOUND_IMPORT_DESCRIPTOR pNext = pBoundImportDirectory;
	while (pNext->TimeDateStamp) {
		printf("TimeDateStamp: %x\n", pNext->TimeDateStamp);
		printf("ModuleName: %s\n", (char*)(pNext->OffsetModuleName + (size_t)pBoundImportDirectory));
		size_t num = pNext->NumberOfModuleForwarderRefs;

		pNext++;
		printf("BoundForwarderRef:\n");
		for (size_t i = 0; i < num; i++) {
			printf("\tModuleName: %s\tTimeDateStamp: %x\n",
				(char*)(pNext->OffsetModuleName + (size_t)pBoundImportDirectory), pNext->TimeDateStamp);
			pNext++;
		}
		printf("************************************************\n");
	}

	free(pFileBuffer);
}

void injectImportDirectory(const char* pFilePath) {
	char DLL_NAME[] = "InjectDll.dll";
	char FUN_NAME[] = "ExportFunction";

	// �ӽ�
	void* pFileBuffer = NULL;
	size_t fileSize = addSection(pFilePath, &pFileBuffer, 0x1000);
	if (!pFileBuffer) {
		printf("�ӽ�ʧ��\n");
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = getFirstSectionHeader(pFileBuffer) + pFileHeader->NumberOfSections - 1;

	// ��ȡImportDescriptor
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 1);
	if (!pImportDescriptor) {
		printf("û�е����\n");
		free(pFileBuffer);
		return;
	}

	// ���㵼����С
	size_t size = 0;
	PIMAGE_IMPORT_DESCRIPTOR pNext = pImportDescriptor;
	while (pNext->Name) {
		size += 20;
		pNext++;
	}
	// �ƶ������
	size_t pStart = (size_t)pFileBuffer + pLastSectionHeader->PointerToRawData;
	memcpy((void*)pStart, pImportDescriptor, size);
	// �޸�ͷ�������rva
	pOptionalHeader32->DataDirectory[1].VirtualAddress = faToRva(pFileBuffer, pStart);
	// ����ImportDescriptor��ʼ��ַ
	PIMAGE_IMPORT_DESCRIPTOR pNewImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pStart + size);
	// �޸�������ImportDescriptor
	pStart += size + 40;
	pNewImportDescriptor->OriginalFirstThunk = faToRva(pFileBuffer, pStart);
	pNewImportDescriptor->FirstThunk = faToRva(pFileBuffer, pStart + 8);
	pNewImportDescriptor->Name = faToRva(pFileBuffer, pStart + 16);
	*((size_t*)pStart) = faToRva(pFileBuffer, pStart + 40);
	*((size_t*)(pStart + 8)) = faToRva(pFileBuffer, pStart + 40);
	memcpy((void*)(pStart + 16), DLL_NAME, strlen(DLL_NAME) + 1);
	memcpy((void*)(pStart + 42), FUN_NAME, strlen(FUN_NAME) + 1);

	// �������ļ���
	char* pNewFilePath = createNewFilePath(pFilePath, "ע�뵼���");
	if (!pNewFilePath) {
		free(pFileBuffer);
		printf("�������ļ���ʧ��\n");
		return;
	}
	writeFileBufferToFile(pNewFilePath, pFileBuffer, fileSize);

	free(pFileBuffer);
	free(pNewFilePath);
}

static void printResourceDirectoryRecursive(PIMAGE_RESOURCE_DIRECTORY pRootRcDir, PIMAGE_RESOURCE_DIRECTORY pRcDir, size_t depth) {
	size_t entryNum = pRcDir->NumberOfIdEntries + pRcDir->NumberOfNamedEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pNextEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRcDir + 1);
	for (size_t i = 0; i < entryNum; i++) {
		for (size_t i = 0; i < depth; i++) {
			printf("  ");
		}

		if (pNextEntry->NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U pDirString = (PIMAGE_RESOURCE_DIR_STRING_U)(pNextEntry->NameOffset + (size_t)pRootRcDir);
			for (size_t i = 0; i < pDirString->Length; i++) {
				printf("%wc", pDirString->NameString[i]);
			}
		}
		else {
			printf("%d", pNextEntry->Id);
		}

		if (!pNextEntry->DataIsDirectory) {
			PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pNextEntry->OffsetToDirectory + (size_t)pRootRcDir);
			printf("  rva: %x, size: %x\n", pDataDir->VirtualAddress, pDataDir->Size);
		}
		else {
			PIMAGE_RESOURCE_DIRECTORY pNextRcDir = (PIMAGE_RESOURCE_DIRECTORY)(pNextEntry->OffsetToDirectory + (size_t)pRootRcDir);
			printf("(%d)\n", pNextRcDir->NumberOfIdEntries + pNextRcDir->NumberOfNamedEntries);
			printResourceDirectoryRecursive(pRootRcDir, pNextRcDir, depth + 1);
		}
		pNextEntry++;
	}
}

void printResourceDirectory(const char* pFilePath) {
	void* pFileBuffer = NULL;
	readPEFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_RESOURCE_DIRECTORY pRootRcDir = (PIMAGE_RESOURCE_DIRECTORY)getDataDirectory(pFileBuffer, 2);
	if (!pRootRcDir) {
		printf("û����Դ��\n");
		free(pFileBuffer);
		return;
	}

	printResourceDirectoryRecursive(pRootRcDir, pRootRcDir, 0);
}

#pragma once

// 读取PE文件到缓冲区
size_t readPEFile(const char* pFilePath, void** ppFileBuffer);

// 打印PE头
void printPEHeader(const char* pFilePath);

// 将FileBuffer复制到ImageBuffer
size_t copyFileBufferToImageBuffer(void* pFileBuffer, void** ppImageBuffer);

// 将ImageBuffer复制到新的缓冲区							
size_t copyImageBufferToNewBuffer(void* pImageBuffer, void** ppNewBuffer);

// 将FileBuffer复制到文件
size_t writeFileBufferToFile(const char* pFilePath, const void* pFileBuffer, size_t fileSize);

// 注入ShellCode
void injectShellCode(const char* pFilePath, size_t sectionNum);

// 增加节
size_t addSection(const char* pFilePath, void** ppNewFileBuffer, size_t addSectionSize);

// 扩大最后一个节
void expandLastSection(const char* pFilePath);

// 合并成一个节
void MergeSections(const char* pFilePath);

// 打印DataDirectory
void printDataDirectory(const char* pFilePath);

// 打印导出表ExportDirectory
void printExportDirectory(const char* pFilePath);

// 通过函数名字获取函数rva
size_t GetFunctionAddrByName(const char* pFilePath, const char* funName);

// 通过函数序号获取函数rva
size_t GetFunctionAddrByOrdinal(const char* pFilePath, size_t funOrdinal);

// 打印重定位表BaseRelocation
void printBaseRelocation(const char* pFilePath);

// 在DLL中新增一个节，并将导出表信息移动到这个新的节中
void moveExportDirectory(const char* pFilePath);

// 在DLL中新增一个节，并将重定位表移动到这个新的节中
void moveBaseRelocation(const char* pFilePath);

// 修改ImageBase
void modifyImageBase(const char* pFilePath, size_t newImageBase);

// 打印导入表
void printImportDirectory(const char* pFilePath);

// 打印绑定导入表
void printBoundImportDirectory(const char* pFilePath);

// 导入表注入
void injectImportDirectory(const char* pFilePath);

// 打印资源表
void printResourceDirectory(const char* pFilePath);
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <Windows.h>
#pragma warning (disable:4996)
#define MESSAGEBOXADDRESS 0x74E57E90
#define SHELLCODELENTH 0x12
#define SECTIONTABLELENTH 0x28
using namespace std;
DWORD ReadPEFile(const char* lpszFile, OUT PVOID* pFileBuffer);
DWORD CopyFileBufferToImageBuffer(LPVOID pFileBuffer, OUT PVOID* pImageBuffer);
DWORD AddImageBuffer(LPVOID pImageBuffer, OUT PVOID* pNewImageBuffer);
DWORD AddFileBuffer(LPVOID pFileBuffer, DWORD filesize, OUT PVOID* pNewFileBuffer);
void ChangePEinfo(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer);
BOOL NewSections(LPVOID pNewImageBuffer, OUT PVOID* pNew_ImageBuffer);
DWORD imageBuffertoNewFileBuffer(LPVOID pNew_ImageBuffer, OUT PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pFileBuffer, DWORD size, LPSTR lpszFile);
void MoveExportTable(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer);
void MoveRelocTable(LPVOID pFileBuffer, OUT PVOID* pNewFileBuffer);
DWORD RVAToFOA(LPVOID pFileBuffer, size_t RVA);
DWORD FOAToVA(LPVOID pFileBuffer, size_t FOA);
void IniPefileDate(LPVOID pFileBuffer);
void PrintInfo(LPVOID pFileBuffer);
VOID operate();
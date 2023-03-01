// readFile.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <winuser.h>
#include <wintrust.h>

char f[80];
DWORD fileSize = 0;

int FOAToRVA(PIMAGE_SECTION_HEADER pSectionHeader,int HeaderSize,int FOAaddress)
{
	int N = 0;
	int Count = 0;
	int RVAaddress = 0;
	int sectionNum = 0;
	int VirtualAddress = 0;
	PIMAGE_SECTION_HEADER pTemSectionHeader = pSectionHeader;
	int sizeOfRaw = 0;
	int actuallySize = 0;
	int pointerOfRaw = 0;
	int deviationAddress =0;

	//������
	if(FOAaddress == 0){return 0;}
	else if(FOAaddress <= HeaderSize){return FOAaddress;}
	else
	{
		while(pTemSectionHeader->Characteristics != 0)
		{
			sectionNum++;

			sizeOfRaw = pTemSectionHeader->SizeOfRawData;
			actuallySize = pTemSectionHeader->Misc.VirtualSize;
			pointerOfRaw = pTemSectionHeader->PointerToRawData;
			VirtualAddress = pTemSectionHeader->VirtualAddress;
			sizeOfRaw > actuallySize ? N=sizeOfRaw : N=actuallySize;

			//1����pointerOfRaw + sizeOfRaw����ȡ����ڵķ�Χ
			//2����FOA�������Χ�Ƚ�,ȷ�����ڽ�
			if(pointerOfRaw <= FOAaddress && FOAaddress <= (pointerOfRaw+sizeOfRaw))
			{
				//3����FOA - �ýڵ�PointToRawData = RVAƫ��
			    deviationAddress = FOAaddress - pointerOfRaw;

				//4��RVAaddress = VirtualAddress + RVAƫ��
				RVAaddress = VirtualAddress + deviationAddress;
				//5���ж��Ƿ� VirtualAddress <= RVA < (VirtualAddress+N) 
				
				if(VirtualAddress <= RVAaddress && RVAaddress <(VirtualAddress+N))
				{
					return RVAaddress;
				}
			}
	
			pTemSectionHeader = (PIMAGE_SECTION_HEADER)((int)pTemSectionHeader + 40);
		}
	}
}

int RVAToFOA(PIMAGE_SECTION_HEADER pSectionHeader,int HeaderSize,int RVAaddress)
{
	int N = 0;
	int Count = 0;
	int FOAaddress = 0;
	int sectionNum = 0;
	int VirtualAddress = 0;
	PIMAGE_SECTION_HEADER pTemSectionHeader = pSectionHeader;
	int sizeOfRaw = 0;
	int actuallySize = 0;


	//������
	if(RVAaddress == 0){return 0;}
	else if(RVAaddress <= HeaderSize){return RVAaddress;}
	else
	{
		while(pTemSectionHeader->Characteristics != 0)
		{
			sectionNum++;
			//1���Ա�SizeOfRawData��Misc��ֵ,˭��ȡ˭

			sizeOfRaw = pTemSectionHeader->SizeOfRawData;
			actuallySize = pTemSectionHeader->Misc.VirtualSize;
			sizeOfRaw > actuallySize ? N=sizeOfRaw : N=actuallySize;
			VirtualAddress = pTemSectionHeader->VirtualAddress;


			//2����VirtualAddress + N����ȡ����ڵķ�Χ
			//3����RVA�������Χ�Ƚ�,ȷ�����ڽ�
			if(VirtualAddress <= RVAaddress && RVAaddress <= (VirtualAddress+N))
			{
				/*Count = 1;
				printf("RVA���ڽ�: %d\n",sectionNum);
				printf("RVAaddress: 0x%X\n",RVAaddress);
				printf("VirtualAddress: 0x%X\n",VirtualAddress);
				printf("VirtualAddress + N: 0x%X\n\n",VirtualAddress+N);*/
				
				//4����ȡ�ھ����е�ƫ��λ��
				int deviationAddress = RVAaddress - VirtualAddress;
			
				//5���øýڵ�PointToRawData + RVA��ƫ�ƣ���RVA��FOA
				FOAaddress = pTemSectionHeader->PointerToRawData + deviationAddress;
				return FOAaddress;
			}
			//if(Count == 1){break;}

			//�����ڣ���������һ����
			pTemSectionHeader = (PIMAGE_SECTION_HEADER)((int)pTemSectionHeader + 40);
		}
	}
}

void tansformTimeStamp(time_t time)
{
	time_t PTime = 0;
    struct tm* timeP;

    PTime = time + (8 * 60 *60);
    timeP = localtime(&PTime);    // ת��
	
	char hbuffer[3];
	char mbuffer[3];
	char sbuffer[3];

	memset(hbuffer, 0, sizeof(hbuffer));
	memset(mbuffer, 0, sizeof(mbuffer));
	memset(sbuffer, 0, sizeof(sbuffer));

	timeP->tm_hour < 10 ? sprintf(hbuffer,"0%d",timeP->tm_hour) : sprintf(hbuffer,"%d",timeP->tm_hour);
	timeP->tm_min < 10 ? sprintf(mbuffer,"0%d",timeP->tm_min) : sprintf(mbuffer,"%d",timeP->tm_min);
	timeP->tm_sec < 10 ? sprintf(sbuffer,"0%d",timeP->tm_sec) : sprintf(sbuffer,"%d",timeP->tm_sec);;	

    printf("%d-%d-%d %s:%s:%s\n",1900+ timeP->tm_year,1+ timeP->tm_mon,timeP->tm_mday, hbuffer, mbuffer,sbuffer);

}

void replace(char * str1, char * str2, char * str3){
    int i, j, k, done, count = 0, gap = 0;
    char temp[80];
    for(i = 0; i < strlen(str1); i += gap){
        if(str1[i] == str2[0]){
            done = 0;
            for(j = i, k = 0; k < strlen(str2); j++, k++){
                if(str1[j] != str2[k]){
                    done = 1;
                    gap = k;
                    break;
                }
            }
            if(done == 0){ // ���ҵ����滻�ַ������滻
                for(j = i + strlen(str2), k = 0; j < strlen(str1); j++, k++){ // ����ԭ�ַ�����ʣ����ַ�
                    temp[k] = str1[j];
                }
                temp[k] = '\0'; // ���ַ��������ַ���
                for(j = i, k = 0; k < strlen(str3); j++, k++){ // �ַ����滻
                    str1[j] = str3[k];
                    count++;
                }
                for(k = 0; k < strlen(temp); j++, k++){ // ʣ���ַ����ؽ�
                    str1[j] = temp[k];
                }
                str1[j] = '\0'; // ���ַ��������ַ���
                gap = strlen(str2);
            }
        }else{
            gap = 1;
        }
    }
    //if(count == 0){
       // printf("Can't find the replaced string!\n");
    //}
    return;
}

char* trim(char *str)
{
	if (str == NULL || *str == '\0')
	{
		return str;
	}
 
	int len = strlen(str);
	char *p = str + len - 1;
	while (p >= str  && isspace(*p))
	{
		*p = '\0';
		--p;
	}

	if (str == NULL || *str == '\0')
	{
		return str;
	}
 
	len = 0;
	p = str;
	while (*p != '\0' && isspace(*p))
	{
		++p;
		++len;
	}
 
	memmove(str, p, strlen(str) - len + 1);

	return str;
}


LPVOID readPEFile(LPSTR filePath)
{
	//�����ļ�ָ��
	FILE *pFile = NULL;
	
	LPVOID pFileBuffer = NULL;

	//���ļ�
	pFile = fopen(filePath,"rb");
	if(!pFile)
	{
		printf("�޷��򿪸ó���\n");
		return NULL;
	}

	//��ָ������ļ�ĩβ
	fseek(pFile,0,SEEK_END);
	//��ȡ�ļ���С
	fileSize = ftell(pFile);
	printf("�ļ���С:0x%X  %dKB",fileSize,fileSize/1024);

	//��ָ������ļ���ͷ
	fseek(pFile,0,SEEK_SET);
	//���仺����
	pFileBuffer = malloc(fileSize);
	if(!pFileBuffer)
	{
		printf("�ڴ����ʧ�ܣ�");
		free(pFileBuffer);
		pFileBuffer = NULL;
		fclose(pFile);
		return NULL;
	}
	size_t flag = fread(pFileBuffer,fileSize,1,pFile);
	if(!flag)
	{
		printf("���ݶ�ȡʧ�ܣ�");
		free(pFileBuffer);
		pFileBuffer = NULL;
		fclose(pFile);
		return NULL;
	}
	
	//��ȡ�ɹ���ر��ļ�
	fclose(pFile);
	return pFileBuffer;
}

//���ļ����� ��ȡ�� ���񻺳�����
//�������ļ�ָ�롢�����С��ͷ��С��DOSͷָ�롢��������ָ��
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,DWORD SizeOfImage,DWORD SizeOfHeaders,PIMAGE_DOS_HEADER pDOSHeader,DWORD NumberOfSection,PIMAGE_SECTION_HEADER pSectionHeader,OUT LPVOID* pImage)
{
	LPVOID pImageBuffer = malloc(SizeOfImage);
	//���ݾ����С����ռ�
	if(!pImageBuffer)
	{
		printf("�ڴ����ʧ�ܣ�");
		return 0;
	}
	//��ʼ��������,��ͷ��ʼ��0
	memset(pImageBuffer,0,SizeOfImage); 
	//�Ȱ�ͷ���뻺������
	memcpy(pImageBuffer,pDOSHeader,SizeOfHeaders);
	//���ݽڱ���٣�ѭ��¼�룬�Ӵ����нڿ�ʼ�ĵط����ϴ����ж����Ĵ�С
	for(int i=0;i<NumberOfSection;i++,pSectionHeader++)
	{
		memcpy((LPVOID)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress),(LPVOID)((DWORD)pDOSHeader + pSectionHeader -> PointerToRawData), pSectionHeader -> SizeOfRawData);
	}

	*pImage = pImageBuffer;
	pImageBuffer = NULL;
	return SizeOfImage;
}

void printHeaders()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDOSHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeaders = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceTable = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pImportBondTable = NULL;
	LPWIN_CERTIFICATE pWinCertificate = NULL;
	PIMAGE_BASE_RELOCATION pReloc = NULL;
	PIMAGE_BOUND_FORWARDER_REF pBondRef = NULL;
	int* functionAddress = NULL;
	short* orderAddress = NULL;
	int* functionName = NULL;
	char* pName = NULL;

	
	//��ȡ·���������ļ���

	char file_name[50];

	pFileBuffer = readPEFile(f);
	if(!pFileBuffer)
	{
		printf("�޷��򿪸ó���\n");
		return ;
	}

	//�ж��Ƿ���MZ��־
	if(*(PWORD)pFileBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("0x%X\n",*(PWORD)pFileBuffer);
		printf("������MZ��ʶ����ȷ�ϴ򿪵��ļ��Ƿ�Ϊ.exe .dll .sys�ļ�");
		//�ͷŶ��ڴ�	
		free(pFileBuffer);
		pFileBuffer = NULL;
		return ;
	}

	printf("\n\n");

	pDOSHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	printf("=======================<<DOSͷ>>=======================\n");
	printf("MZ��ʶ: %c%c\n",pDOSHeader ->e_magic,*((char*)pFileBuffer+1));
	printf("PEƫ��: 0x%X\n",pDOSHeader ->e_lfanew);
	if(*((PWORD)((DWORD)pFileBuffer+pDOSHeader ->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������PE��ʶ,�ļ���������");
		//�ͷŶ��ڴ�	
		free(pFileBuffer);
		pFileBuffer = NULL;
		return ;
	}

	pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDOSHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeaders)+4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	int HeaderSize = pOptionHeader ->SizeOfHeaders;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

	//��ӡNTͷ
	printf("=======================<<NTͷ>>=======================\n");
	printf("NTͷ: %c%c\n",pNTHeaders ->Signature,*((char*)(pDOSHeader ->e_lfanew+(DWORD)pFileBuffer+1)));
	printf("=======================<<PEͷ>>=======================\n");
	printf("�ڵ�����: %d\n",pPEHeader ->NumberOfSections);
	printf("�ļ�����ʱ��: ");
	tansformTimeStamp(pPEHeader->TimeDateStamp);
	printf("��ѡPEͷ��С: 0x%X\n",pPEHeader ->SizeOfOptionalHeader);
	
	if(((pPEHeader ->Characteristics) & 0x8000) > 0x8000){
		printf("Characteristics: 0x%X\n�ļ��в������ض�����Ϣ,���ļ�����IAT��\n",pPEHeader->Characteristics);
	}else{
		printf("Characteristics: 0x%X\n",pPEHeader->Characteristics);
	}
	
	printf("=======================<<��ѡPEͷ>>=======================\n");
	if(pOptionHeader->Magic == 0x20b)
	{printf("��ѡPEͷ: 0x%X   ���ļ���32λ�µ�PE�ļ�\n",pOptionHeader ->Magic);}
	else if(pOptionHeader->Magic == 0x10b)
	{printf("��ѡPEͷ: 0x%X   ���ļ���64λ�µ�PE�ļ�\n",pOptionHeader ->Magic);}
	else{
		printf("��ѡPEͷ: 0x%X   ���ļ���ROM����\n",pOptionHeader ->Magic);
	}
	printf("�����ַ: 0x%X\n",pOptionHeader ->ImageBase);
	printf("OEP(RVA): 0x%X\n",pOptionHeader ->AddressOfEntryPoint);
	printf("OEP(FOA): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->AddressOfEntryPoint));
	printf("�ڴ�ڶ���: 0x%X\n",pOptionHeader ->SectionAlignment);
	printf("���̽ڶ���: 0x%X\n",pOptionHeader ->FileAlignment);
	if(((pOptionHeader ->SizeOfImage)/1024) > 1){
		printf("�ڴ澵���С: 0x%X %dMB %dKB\n",pOptionHeader ->SizeOfImage,(pOptionHeader ->SizeOfImage)/1024/1024,(pOptionHeader ->SizeOfImage)/1024%1024);
	}else{
		printf("�ڴ澵���С: 0x%X %dMB%dKB\n",pOptionHeader ->SizeOfImage,(pOptionHeader ->SizeOfImage)/1024);
	}
	printf("ͷ��С: 0x%X %dKB\n",pOptionHeader ->SizeOfHeaders,(pOptionHeader ->SizeOfHeaders)/1024);
	if(((pOptionHeader ->CheckSum)/1024) > 1){
		printf("У���: 0x%X %dMB %dKB\n",pOptionHeader ->CheckSum,(pOptionHeader ->CheckSum)/1024/1024,(pOptionHeader ->CheckSum)/1024%1024);
	}else{
		printf("У���: 0x%X %dKB\n",pOptionHeader ->CheckSum,(pOptionHeader ->CheckSum)/1024);
	}

	

	printf("=====================����Ϣ=====================\n\n");
	for(int i=0;i<15;i++)
	{
		printf("================================\n\n");
		switch(i)
		{
			case 0:
				printf("��������Ϣ: \n");
				break;
			case 1:
				printf("ע: ������������ͷ��?��ͷ��˵���ú������ѱ����������û��ʹ��extern 'C'������ʹ��������\n\n");
				printf("�������Ϣ: \n");
				break;
			case 2:
				printf("��Դ����Ϣ: \n");
				break;
			case 3:
				printf("�쳣����Ϣ: \n");
				break;
			case 4:
				printf("��ȫ֤����Ϣ: \n");
				break;
			case 5:
				printf("�ض�λ����Ϣ: \n");
				break;
			case 6:
				printf("���Ա���Ϣ: \n");
				break;
			case 7:
				printf("��Ȩ����Ϣ: \n");
				break;
			case 8:
				printf("ȫ��ָ�����Ϣ: \n");
				break;
			case 9:
				printf("TLS����Ϣ: \n");
				break;
			case 10:
				printf("�������ñ���Ϣ: \n");
				break;
			case 11:
				printf("�󶨵������Ϣ: \n");
				break;
			case 12:
				printf("IAT����Ϣ: \n");
				break;
			case 13:
				printf("�ӳٵ������Ϣ: \n");
				break;
			case 14:
				printf("COM��Ϣ��: \n");
				break;
		}
		if(i == 4){
			printf("FOA:                  0x%X\n",pOptionHeader ->DataDirectory[i].VirtualAddress);
			printf("Size:                 0x%X\n\n",pOptionHeader ->DataDirectory[i].Size);
		}else{
			//�����pSectionHeader��λ���� �ڱ�ƫ��λ��+pFileBuffer
			printf("FOV(δ����ImageBase): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[i].VirtualAddress));
			printf("VirtualAddress:       0x%X\n",pOptionHeader ->DataDirectory[i].VirtualAddress);
			printf("Size:                 0x%X\n\n",pOptionHeader ->DataDirectory[i].Size);
		}

		//������
		if(i==0)
		{	
			if((pOptionHeader ->DataDirectory[0].VirtualAddress) == 0x1000) printf("���ļ�������������\n\n");
			//�����������ھʹ�ӡ������
			if((pOptionHeader ->DataDirectory[0].VirtualAddress) != 0 && (pOptionHeader ->DataDirectory[0].VirtualAddress) != 0x1000)
			{
				//�Ѵ����б��λ�ø�ֵ��ָ��
				pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[0].VirtualAddress)));
				pName = (char*)((pExportTable->Name + (DWORD)pFileBuffer)+1);

				//printf("pName: 0x%X\n",pName);
				//printf("fileSize: 0x%X\n",fileSize);
				//�÷��������
				//�����ֵ�ַ�����ļ���С�������ֵ�ַ��FOVС���ļ���С
				//�����ֵ�ַС���ļ���С
				//�����ֵ�ַ�����ļ���С
				if(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name)< fileSize)
				{
					pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name) + (DWORD)pFileBuffer );
					printf("����������:              ");

					while(*(pName)!=0)
					{
						printf("%c",*pName);
						pName++;
					}

					printf("\n");
				}else{printf("��������Ϣ����\n\n");}

				//�ͷ�ָ��
				pName=NULL;

				printf("�������������ڵ�ַ:      0x%X\n",pExportTable->Name);
				printf("�������������ڵ�ַ(FOV): 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name));
				printf("��Ż���: 0x%X\n",pExportTable->Base);
				printf("��������: %d\n",pExportTable->NumberOfFunctions);
				printf("��������������: %d\n\n",pExportTable->NumberOfNames);
				printf("������RVA: 0x%X\n",pExportTable->AddressOfFunctions);
				printf("������FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfFunctions));
				printf("���Ʊ�RVA: 0x%X\n",pExportTable->AddressOfNames);
				printf("���Ʊ�FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNames));
				printf("��ű�RVA: 0x%X\n",pExportTable->AddressOfNameOrdinals);
				printf("��ű�FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNameOrdinals));

				

				functionName = (int*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNames)));
				
				functionAddress = (int*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfFunctions)));
				int* tempFunctionName = functionName;

				//����������ַ��
				for(int i=0;i<pExportTable->NumberOfFunctions;i++)
				{
					orderAddress = (short*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNameOrdinals)));
					printf("����:%d",i);
					printf("  ������ַ: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*functionAddress));

					//ƥ����ű�
					for(int j=0;j<pExportTable->NumberOfNames;j++)
					{
						if(i==(*orderAddress))
						{
							printf("  �������: @%d",(*orderAddress)+pExportTable->Base);
							break;
						}else{
							orderAddress++;
						}
					}

					//ƥ�亯�����Ʊ�
					for(int k=0;k<pExportTable->NumberOfNames;k++)
					{
						if((*orderAddress)==k)
						{
							//printf("  functionName(RVA): 0x%X",*functionName);
							if(RVAToFOA(pSectionHeader,HeaderSize,*functionName) < fileSize)
							{		
								
								printf("  ������: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*functionName));
								pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,*functionName) + (DWORD)pFileBuffer);
								printf("  ������: ");

								while(*(pName)!=0)
								{
									printf("%c",*pName);
									pName++;
								}

								printf("\n\n");
							}else{printf("   �������Ʊ���Ϣ����\n\n");}

							functionName++;
							break;

						}else{
							tempFunctionName++;
						}
					}
					functionAddress++;
				}

				pExportTable = NULL;
			}
		}


		//�����
		if(i==1)
		{
			//�����������ھʹ�ӡ�����
			if((pOptionHeader ->DataDirectory[1].VirtualAddress) != 0)
			{
				//�Ѵ����б��λ�ø�ֵ��ָ��
				pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[1].VirtualAddress)));
				pName = (char*)(pImportTable->Name + (DWORD)pFileBuffer);
				UINT hexNum = 0x80000000;
				

				//�������ŵ����
				while((pImportTable ->OriginalFirstThunk)!=0)
				{
					int sum = 1;
					int* pThunk = (int*)(RVAToFOA(pSectionHeader,HeaderSize,pImportTable->OriginalFirstThunk) + (DWORD)pFileBuffer);
					char* pFunctionName = (char*)((RVAToFOA(pSectionHeader,HeaderSize,*pThunk) + (DWORD)pFileBuffer) + 2);

					
					//������������
					if(RVAToFOA(pSectionHeader,HeaderSize,pImportTable->Name)< fileSize)
					{
						pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,pImportTable->Name) + (DWORD)pFileBuffer );
						printf("���������:      ");

						while(*(pName)!=0)
						{
							printf("%c",*pName);
							pName++;
						}

						printf("\n");
					}else{printf("�������Ϣ����\n\n");}

					//�ͷ�ָ��
					pName=NULL;

					printf("������ַ:      0x%X\n",(int)pImportTable-(int)pFileBuffer);
					printf("INT���ַ:       0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pImportTable->OriginalFirstThunk));
					printf("IAT���ַ:       0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pImportTable->FirstThunk));
					printf("ʱ���: %d",pImportTable->TimeDateStamp);
					if(pImportTable->TimeDateStamp == 0){printf("        ��dllδ�󶨣���IAT���ֵΪ�ǵ�ַ\n\n");}
					else{printf("        �� dll �Ѱ󶨣�IAT���ڰ�����ֵַ\n\n");}

					//����INT��
					while(*pThunk!=0)
					{
						printf("���: %d",sum);
						
						//�����ͷΪ1��������
						if((*pThunk) >= hexNum)
						{
							//ȡ����31λ��ֵ
							*pThunk = (*pThunk)& 0x0FFF;
							printf("   �������: 0x%X  %d",*pThunk,*pThunk);
						}else
						{
							//�����ͷΪ0���������
							printf("   ��������ַ: 0x%X",*pThunk +2);
							printf("   �������ļ��е�ַ: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*pThunk) +2);
							printf("   ��������: ");
							while(*pFunctionName!=0)
							{
								printf("%c",*pFunctionName);
								pFunctionName++;
							}

							sum++;
						}
						
						printf("\n\n");
						pThunk++;
						pFunctionName = (char*)((RVAToFOA(pSectionHeader,HeaderSize,*pThunk) + (DWORD)pFileBuffer) + 2);
					}
					printf("**********************\n\n");
					pImportTable++;
				}

				pImportTable = NULL;
			}
		}


		//��Դ��
		if(i==2)
		{
			int entryNum;
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry;
			int idTable[23]= {1,2,3,4,5,6,7,8,9,10,11,12,14,16,17,19,20,21,22,23,24};
			char* resTypeMean[23] ={ "���ָ��", "λͼ", "ͼ��", "�˵�", "�Ի���", "�ַ����б�","����Ŀ¼", "����", "��ݼ�", "�Ǹ�ʽ����Դ", "��Ϣ�б�",
									"���ָ����", "ͼ����","�汾��Ϣ","��.rc������ͷ�ļ�","���弴����Դ","VXD","�����α�","����ͼ��","HTML ��Դ","���г����嵥"};	//windows�Ѷ�������
			char* resTypeName[23]={"RT_CURSOR","RT_BITMAP","RT_ICON","RT_MENU","RT_DIALOG","RT_STRING","RT_FONTDIR","RT_FONT","RT_ACCELERATOR","RT_RCDATA","RT_MESSAGETABLE",
									"RT_GROUP_CURSOR","RT_GROUP_ICON","RT_VERSION","RT_DLGINCLUDE","RT_PLUGPLAY","RT_VXD","RT_ANICURSOR","RT_ANIICON","RT_HTML","RT_MANIFEST"};


			//�����������ھʹ�ӡ�����
			if((pOptionHeader ->DataDirectory[2].VirtualAddress) != 0)
			{
				pResourceTable = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[2].VirtualAddress)));
				//��ȡ��Դ�������
				entryNum = pResourceTable->NumberOfIdEntries + pResourceTable->NumberOfNamedEntries;

				//��λ��Դ����ʼ�ص�
				 pEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTable+1);
				 
				 if(entryNum < 1000){
					 printf("�������: %1d  �ַ�������: %1d\n��һ����ԴĿ¼��ʼ��ַ:   0x%X \n",pResourceTable->NumberOfIdEntries,pResourceTable->NumberOfNamedEntries,(DWORD)pResourceTable-(DWORD)pFileBuffer);	
					 printf("��Դ��(���)��ʼ��ַ:0x%X\n\n",(DWORD)pEntry-(DWORD)pFileBuffer);	

					 //�ж��ǲ���exe�ļ�
					 if(strstr(f,"exe")!=NULL){

						 //��� ���� [discardble] �ļ���ַ    discardble��������ڲ��ø���Դʱж�ص�
						 //1001 icon  "icon.ico"
						 //TITLE_ICON icon "cover.ico"

						 //��һ��
						 //������Դ��(���)
						 for(int i=0;i<entryNum;i++){

							 if(!pEntry[i].NameIsString) //���NameIsStringΪ0����Name��λΪ0,��31Ϊ��Ӧ�ľ�������id		��WindowsԤ�ȶ����������
							 {

								 for(int j=0;j<(sizeof(idTable)/4);j++){
									 if(pEntry[i].Id == idTable[j]){

										 printf("\n");	
										 printf("----------------------------------------------------------------------------------\n");	
										 switch(pEntry[i].Id)
										 {
										 case 1:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[0],resTypeMean[0]);
											 break;
										 case 2:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[1],resTypeMean[1]);
											 break;
										 case 3:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[2],resTypeMean[2]);
											 break;
										 case 4:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[3],resTypeMean[3]);
											 break;
										 case 5:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[4],resTypeMean[4]);
											 break;
										 case 6:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[5],resTypeMean[5]);
											 break;
										 case 7:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[6],resTypeMean[6]);
											 break;
										 case 8:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[7],resTypeMean[7]);
											 break;
										 case 9:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[8],resTypeMean[8]);
											 break;
										 case 10:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[9],resTypeMean[9]);
											 break;
										 case 11:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[10],resTypeMean[10]);
											 break;
										 case 12:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[11],resTypeMean[11]);
											 break;
										 case 14:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[12],resTypeMean[12]);
											 break;
										 case 16:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[13],resTypeMean[13]);
											 break;
										 case 17:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[14],resTypeMean[14]);
											 break;
										 case 19:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[15],resTypeMean[15]);
											 break;
										 case 20:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[16],resTypeMean[16]);
											 break;
										 case 21:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[17],resTypeMean[17]);
											 break;
										 case 22:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[18],resTypeMean[18]);
											 break;
										 case 23:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[19],resTypeMean[19]);
											 break;
										 case 24:
											 printf("%d-%s-%s\n",pEntry[i].Id,resTypeName[20],resTypeMean[20]);
											 break;
										 default :
											 printf("�Զ�����Դ���͵�id: %d\n",pEntry[i].Id );	
											 break;
										 }

									 }
								 }


							 }else{

								 //���NameIsStringΪ1��˵����������Name�������ĵ�31����ƫ�ƣ�ƫ�Ƽ���Դ����ʼ��ַָ��һ��Unicode�ṹ��		 ��һ���Զ�����������
								 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable+pEntry[i].NameOffset);
								 WCHAR typeName[20];
								 memcpy_s(typeName,20,pUnicodeString->NameString,pUnicodeString->Length*sizeof(WCHAR));
								 printf("��������:%ls\n",typeName);	
							 }

							 //�ڶ���
							 //������Դ��(Ψһ���)
							 if(pEntry[i].DataIsDirectory){  //���DataIsDirectory��1��������������rDirectory,ָ����һ���ṹĿ¼���׵�ַ  ��һ�㣬�ڶ�������ֵĬ��Ϊ1

								 PIMAGE_RESOURCE_DIRECTORY pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceTable + pEntry[i].OffsetToDirectory);
								 PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir+1);
								 int entryNum2 = pResourceDir->NumberOfIdEntries+pResourceDir->NumberOfNamedEntries;


								 printf(" |\n");	
								 printf("  --�ڶ�����ԴĿ¼��ʼ��ַ:   0x%X\n",(DWORD)pResourceDir-(DWORD)pFileBuffer);	
								 printf("    ��Դ��(Ψһ���)��ʼ��ַ: 0x%X\n",(DWORD)pEntry2 - (DWORD)pFileBuffer);
								 printf("    �������: %1d  �ַ�������:  %1d\n\n",pResourceDir->NumberOfIdEntries,pResourceDir->NumberOfNamedEntries);	

								 //������Դ��
								 for(int k=0;k<entryNum2;k++){
									 if(!pEntry2[k].NameIsString){
										 printf("    id: %d\n",pEntry2[k].Id);	
									 }else{

										 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable + (pEntry2[k].NameOffset));
										 WCHAR idName[20];
										 memcpy(idName,pUnicodeString->NameString,(pUnicodeString->Length)*sizeof(WCHAR));
										 printf("    �Զ�����Դ: %s\n",idName);	

									 }

									 //������
									 //������Դ��(����ҳ����������)
									 if(pEntry2[k].DataIsDirectory){
										 PIMAGE_RESOURCE_DIRECTORY pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceTable + pEntry2[k].OffsetToDirectory);
										 PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2+1);
										 int entryNum3 = pResourceDir2->NumberOfIdEntries+pResourceDir2->NumberOfNamedEntries;

										 printf("     |\n");	
										 printf("      --��������ԴĿ¼��ʼ��ַ:  0x%X\n",(DWORD)pResourceDir2-(DWORD)pFileBuffer);	
										 printf("        ��Դ��(����ҳ)��ʼ��ַ:  0x%X\n",(DWORD)pEntry3 - (DWORD)pFileBuffer);
										 printf("        �������: %1d  �ַ�������: %1d\n\n",pResourceDir2->NumberOfIdEntries,pResourceDir2->NumberOfNamedEntries);	

										 for(int t=0;t<entryNum3;t++){
											 if(!pEntry3[t].NameIsString){

												 switch(pEntry3[t].Id)
												 {
												 case 1025:
													 printf("        ���Ա��:    %d-��������\n",pEntry3[t].Id);
													 break;
												 case 1028:
													 printf("        ���Ա��:    %d-���ķ���\n",pEntry3[t].Id);
													 break;
												 case 1033:
													 printf("        ���Ա��:    %d-Ӣ��\n",pEntry3[t].Id);
													 break;
												 case 1041:
													 printf("        ���Ա��:    %d-����\n",pEntry3[t].Id);
													 break;
												 case 2052 :
													 printf("        ���Ա��:    %d-���ļ���\n",pEntry3[t].Id);
													 break;
												 }

											 }else{

												 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable+pEntry3[t].NameOffset);
												 WCHAR languageName[20];
												 memcpy_s(languageName,20,pUnicodeString->NameString,pUnicodeString->Length*sizeof(WCHAR));
												 printf("        ����: %s",languageName);	

											 }

											 if(!pEntry3[t].DataIsDirectory){

												 PIMAGE_RESOURCE_DATA_ENTRY pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResourceTable+pEntry3[t].OffsetToData);
												 LPVOID pSourceBlock = (LPVOID)((DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,pResData->OffsetToData));

												 printf("        �������ַ:       0x%X\n",(DWORD)pSourceBlock-(DWORD)pFileBuffer);	
												 printf("        ��Դ���ݿ��RVA:  0x%X\n",pResData->OffsetToData);	
												 printf("        ��Դ���ݿ��FOA:  0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pResData->OffsetToData));	
												 printf("        ��Դ���ݿ�ĳ���: 0x%X\n\n",pResData->Size);	

												 short* pFlag;

												 switch(pEntry[i].Id)
												 {
													 //case 3:
													 //���ͼ����ͷ�� 89 50 4E 47 ˵����png�ļ���ֱ���������ϴ���һ���ļ�д��

												 case 4:
													 pFlag = (short*)((int)pSourceBlock + 4);
													 if(*pFlag == 0x10){
														 printf("        ����һ�������˵�\n");	
													 }else if(*pFlag == 0){
														 printf("        ����һ����ͨ�˵�\n");	
													 }
													 break;
												 case 16:
													 LPVOID pVersion = (LPVOID)((int)pSourceBlock + 97);
													 //�����ַ����StringFileInfo����ʼλ��
													 break;

												 }


											 }

										 }
										 printf("\n");	

									 }


								 }

							 }


						 }


					 }
				 }else{
					printf("���ļ���Դ������\n\n");	
				}
				 
			}
		
		}

		//��ȫ֤����Ϣ
		if(i==4){

			if(((DWORD)pFileBuffer + pOptionHeader ->DataDirectory[4].VirtualAddress + pOptionHeader ->DataDirectory[4].Size) <= (DWORD)pFileBuffer + fileSize){
				pWinCertificate = (LPWIN_CERTIFICATE)((DWORD)pFileBuffer + pOptionHeader ->DataDirectory[4].VirtualAddress);
				printf("֤�鳤��:             0x%X\n",pWinCertificate->dwLength);	
				printf("֤��汾��:           0x%X\n",pWinCertificate->wRevision);	
				printf("֤������:             0x%X\n\n",pWinCertificate->wCertificateType);	
				int length;

				//���֤�����ݴ�С��Ϊ8�ı���,����ȡ8�ı���
				if((pWinCertificate->dwLength)%8 != 0){
					length = ((pWinCertificate->dwLength)-(pWinCertificate->dwLength%8))+8;
					if(length != pOptionHeader ->DataDirectory[4].Size){
						printf("֤���ѱ��ƻ�\n\n");	
					}
				}
			}else{
				printf("֤���ѱ��ƻ�\n\n");	
			}
		}

		//Ctrl + K + C ע��  Ctrl + K + U ȡ��ע��

		//�ض�λ��
		if(i==5)
		{
			printf("�Ƿ��ӡ�ض�λ��");	
			if(getchar() == 'y'){
				short* pOffset = NULL;
				pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[5].VirtualAddress));
				int count = 0;
				while(pReloc->VirtualAddress != 0)
				{	
					count++;
					pOffset = (short*)((int)pReloc + 8);
					printf("��%d���ض�λ�����ʼ�����ַ: 0x%X\n",count,pReloc->VirtualAddress);
					printf("��%d���ض�λ�����ʼ�ļ���ַ: 0x%X\n",count, RVAToFOA(pSectionHeader,HeaderSize,pReloc->VirtualAddress));
					printf("��%d���ض�λ��Ĵ�С: 0x%X\n",count,pReloc->SizeOfBlock);
					printf("ƫ������: %d\n\n",((pReloc->SizeOfBlock)-8)/2);

					printf("����Ϊ��Ҫ�ض�λ�ĵ�ַ ��ƫ�Ƶ�ַ�����ļ��еĵ�ַ\n");
					printf("�ļ��е�ƫ�Ƶ�ַ���Լ�����3���ֽھ�����Ҫ���޸ĵľ��Ե�ַ\n\n");
					for(int i=0;i<(((pReloc->SizeOfBlock)-8)/2);i++)
					{
						//printf("ƫ��ֵ: 0x%X 0x%X\n",*pOffset,*pOffset>>12);
						if(*pOffset!=0 && (*pOffset>>12) == 0x3)
						{
							printf("ƫ�Ƶ�ַ: 0x%X \t�ļ��е�ƫ�Ƶ�ַ��0x%X\n",(pReloc->VirtualAddress) + (*pOffset & 0x0fff),RVAToFOA(pSectionHeader,HeaderSize,((pReloc->VirtualAddress) + (*pOffset & 0x0fff))));
							pOffset++;
						}else if(*pOffset!=0 && (*pOffset>>12) == 0x0){
							printf("�����޸ĵ�ƫ��: 0x%X\n",(pReloc->VirtualAddress) + *pOffset);
						}else{
							printf("��������: 0x%X\n",*pOffset);
						}
					}
					printf("\n",((pReloc->SizeOfBlock)-8)/2);
					pReloc = (PIMAGE_BASE_RELOCATION)((int)pReloc + pReloc->SizeOfBlock);
				}
			}
		}


		//����󶨱�
		if(i==11)
		{	
			int sum = 0;
			PIMAGE_BOUND_IMPORT_DESCRIPTOR pTemImportBondTable = NULL;
			if((pOptionHeader ->DataDirectory[11].VirtualAddress) != 0)
			{
		
				pImportBondTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[11].VirtualAddress)));

				
				//�����󶨵����
				while(pImportBondTable->TimeDateStamp != 0)
				{
					sum++;
					printf("����: %d\n",sum);

					pTemImportBondTable = pImportBondTable;

					//���DLL����
					if(RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName))< fileSize)
					{
						pName = (char*)( (DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName)) );
						printf("DLL����: ");

						while(*(pName)!=0)
						{
							printf("%c",*pName);
							pName++;
						}

						printf("\n");
					}else{printf("�󶨵������Ϣ����\n\n");}

					//�ͷ�ָ��
					pName=NULL;


					printf("DLL���Ƶ�ַ(FOV): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName) ) );
					printf("�ļ�����ʱ��:");
					tansformTimeStamp(pImportBondTable->TimeDateStamp);
					printf("DLL�а󶨵�DLL������%d\n\n",pImportBondTable->NumberOfModuleForwarderRefs);


					for(int i=0;i<pImportBondTable->NumberOfModuleForwarderRefs;i++)
					{
						pTemImportBondTable++;
						pBondRef = (PIMAGE_BOUND_FORWARDER_REF)pImportBondTable;
					
						//���DLL�е�DLL��Ϣ
						if(RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pBondRef->OffsetModuleName))< fileSize)
						{
							printf("������DLL�����󶨵�DLL��Ϣ: \n");
							printf("------------------------------ \n");
							pName = (char*)( (DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pBondRef->OffsetModuleName)) );
							printf("DLL����: ");

							while(*(pName)!=0)
							{
								printf("%c",*pName);
								pName++;
							}

							printf("\n");
						}else{printf("�󶨵������Ref����Ϣ����\n\n");}

						printf("�ļ�����ʱ��:");
						tansformTimeStamp(pBondRef ->TimeDateStamp);

					}

					printf("**************************\n\n");
					//���DLL�л�����DLL����ô��һ���󶨵�����λ�þ���һ��ʼ�󶨵�����λ�ü�������DLL�ĸ���
					if(pImportBondTable->NumberOfModuleForwarderRefs != 0)
					{
						pImportBondTable+=pImportBondTable->NumberOfModuleForwarderRefs;
					}else{
						pImportBondTable++;
					}
					
				}
				
				pImportBondTable = NULL;
				pTemImportBondTable = NULL;
			}
		}




		printf("================================\n\n");
	}


	
	int sectionStartingPosition = pDOSHeader->e_lfanew+24+pPEHeader ->SizeOfOptionalHeader;
	int sectionNum = 0;
	
	printf("=======================<<�ڱ�>>=======================\n");
	while(pSectionHeader->Characteristics != 0 && (sectionNum<(pPEHeader ->NumberOfSections))){
		
	printf("\n");
		sectionNum++;
		printf("=========��%d=========\n\n",sectionNum);

		char snBuffer[8];
		memcpy(snBuffer,(void*)((int)pFileBuffer+sectionStartingPosition),8);
		printf("����: %s\n",snBuffer);
		
		if(strcmp(snBuffer,".text")==0){
			printf("�����\n");	
		}else if(strcmp(snBuffer,".rdata")==0){
			printf("������\n");
		}else if(strcmp(snBuffer,".data")==0){
			printf("���ݽ�\n");
		}else if(strcmp(snBuffer,".rsrc")==0){
			printf("��Դ���\n");
		}else if(strcmp(snBuffer,".reloc")==0){
			printf("�ض�λ���\n");
		}else if(strcmp(snBuffer,".tls")==0){
			printf("�̱߳��ش洢���\n");
		}else if(strcmp(snBuffer,".edata")==0){
			printf("�������ݽ�\n");
		}else if(strcmp(snBuffer,".idata")==0){
			printf("�������ݽ�\n");
		}else if(strcmp(snBuffer,".pdata")==0){
			printf("�쳣�����ݽ�\n");
		}else{
			printf("δ֪��\n");
		}

		printf("\n");
		printf("�ڱ����ʼλ��: 0x%X\n",sectionStartingPosition);
		printf("�ڵ�ʵ�ʴ�С: 0x%X\n",pSectionHeader ->Misc.VirtualSize);
		printf("�ý����ڴ��е�ƫ�Ƶ�ַ(���Ͼ����ַ): 0x%X\n",pOptionHeader->ImageBase+pSectionHeader ->VirtualAddress);
		printf("�ý����ڴ��е�ƫ�Ƶ�ַ: 0x%X\n",pSectionHeader ->VirtualAddress);
		printf("�ý��ڴ����е�ƫ�Ƶ�ַ: 0x%X\n",pSectionHeader ->PointerToRawData);
		printf("�ý��ڴ����ж����Ĵ�С: 0x%X\n",pSectionHeader ->SizeOfRawData);
		printf("�ý��ڴ����н���λ��: 0x%X\n",(pSectionHeader ->PointerToRawData + pSectionHeader ->SizeOfRawData)-16);
		printf("\n");
		printf("�ý��ص㣺\n");

		//�����ڶ�λ
		long long int symbol = (pSectionHeader ->Characteristics)| 0xFFFFFF00;
		symbol = symbol - 0xFFFFFF00;
		symbol = symbol>>4;

		switch(symbol)
		{
			case 2:
				printf("�ýڰ�����ִ�д���\n");
				break;
			case 4:
				printf("�ýڰ����ѳ�ʼ������\n");
				break;
			case 6:
				printf("�ýڰ�����ִ�д�����ѳ�ʼ������\n");
				break;
			case 8:
				printf("�ýڰ���δ��ʼ������\n");
				break;
			case 0xA:
				printf("�ýڰ�����ִ�д����δ��ʼ������\n");
				break;
			case 0xC:
				printf("�ýڰ����ѳ�ʼ�����ݺ�δ��ʼ������\n");
				break;
			case 0xE:
				printf("�ýڰ����ѳ�ʼ�����ݺ�δ��ʼ�������Լ���ִ�д���\n");
				break;
		}

		//���λ
		long long int first = (pSectionHeader ->Characteristics)>>28;
		if(first==1){printf("�ý�δ����\n");}
		else if(first==2){printf("�ýڿ�ִ��\n\n");}
		else if(first==4){printf("�ýڿɶ�\n\n");}
		else if(first==6){printf("�ýڿɶ���ִ��\n\n");}
		else if(first==8){printf("�ýڿ�д\n\n");}
		else if(first==0xA){printf("�ýڿ�д��ִ��\n\n");}
		else if(first==0xC){printf("�ýڿɶ���д\n\n");}
		else if(first==0xE){printf("�ýڿɶ���д��ִ��\n\n");}
		else{ ;}	
		pSectionHeader = (PIMAGE_SECTION_HEADER)((int)pSectionHeader + 40);
		sectionStartingPosition = sectionStartingPosition + 40;
		printf("====================\n\n");
	}
	printf("�ܽ�����%d\n",sectionNum);
	free(pFileBuffer);
	pFileBuffer = NULL;
}



int _tmain(int argc, _TCHAR* argv[])
{
	printf("�������ļ�·��: \n");
	while(gets(f) != NULL){
		replace(f,"\""," ");
		trim(f);

		printHeaders();
		system("pause");

		system("Cls");
		printf("�������ļ�·��: \n");
	}
	
}




//ͷ��СС���ڴ����ʱ���ھʹ� �ڴ�����С��ʼ
//��ͷ��С�����ڴ����ʱ����ͷ��С%�ڴ��С��(���+1)*�ڴ��С��
//�������ж�Misc��Misc��ֵ�Ĵ�С�Ƿ񳬹��ڴ���룬�������ɵĺ�����һ��
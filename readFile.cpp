// readFile.cpp : 定义控制台应用程序的入口点。
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

	//遍历节
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

			//1、用pointerOfRaw + sizeOfRaw，获取这个节的范围
			//2、用FOA和这个范围比较,确定所在节
			if(pointerOfRaw <= FOAaddress && FOAaddress <= (pointerOfRaw+sizeOfRaw))
			{
				//3、用FOA - 该节的PointToRawData = RVA偏移
			    deviationAddress = FOAaddress - pointerOfRaw;

				//4、RVAaddress = VirtualAddress + RVA偏移
				RVAaddress = VirtualAddress + deviationAddress;
				//5、判断是否 VirtualAddress <= RVA < (VirtualAddress+N) 
				
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


	//遍历节
	if(RVAaddress == 0){return 0;}
	else if(RVAaddress <= HeaderSize){return RVAaddress;}
	else
	{
		while(pTemSectionHeader->Characteristics != 0)
		{
			sectionNum++;
			//1、对比SizeOfRawData和Misc的值,谁大取谁

			sizeOfRaw = pTemSectionHeader->SizeOfRawData;
			actuallySize = pTemSectionHeader->Misc.VirtualSize;
			sizeOfRaw > actuallySize ? N=sizeOfRaw : N=actuallySize;
			VirtualAddress = pTemSectionHeader->VirtualAddress;


			//2、用VirtualAddress + N，获取这个节的范围
			//3、用RVA和这个范围比较,确定所在节
			if(VirtualAddress <= RVAaddress && RVAaddress <= (VirtualAddress+N))
			{
				/*Count = 1;
				printf("RVA所在节: %d\n",sectionNum);
				printf("RVAaddress: 0x%X\n",RVAaddress);
				printf("VirtualAddress: 0x%X\n",VirtualAddress);
				printf("VirtualAddress + N: 0x%X\n\n",VirtualAddress+N);*/
				
				//4、获取在镜像中的偏移位置
				int deviationAddress = RVAaddress - VirtualAddress;
			
				//5、用该节的PointToRawData + RVA的偏移，即RVA的FOA
				FOAaddress = pTemSectionHeader->PointerToRawData + deviationAddress;
				return FOAaddress;
			}
			//if(Count == 1){break;}

			//不存在，就跳到下一个节
			pTemSectionHeader = (PIMAGE_SECTION_HEADER)((int)pTemSectionHeader + 40);
		}
	}
}

void tansformTimeStamp(time_t time)
{
	time_t PTime = 0;
    struct tm* timeP;

    PTime = time + (8 * 60 *60);
    timeP = localtime(&PTime);    // 转换
	
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
            if(done == 0){ // 已找到待替换字符串并替换
                for(j = i + strlen(str2), k = 0; j < strlen(str1); j++, k++){ // 保存原字符串中剩余的字符
                    temp[k] = str1[j];
                }
                temp[k] = '\0'; // 将字符数组变成字符串
                for(j = i, k = 0; k < strlen(str3); j++, k++){ // 字符串替换
                    str1[j] = str3[k];
                    count++;
                }
                for(k = 0; k < strlen(temp); j++, k++){ // 剩余字符串回接
                    str1[j] = temp[k];
                }
                str1[j] = '\0'; // 将字符数组变成字符串
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
	//定义文件指针
	FILE *pFile = NULL;
	
	LPVOID pFileBuffer = NULL;

	//打开文件
	pFile = fopen(filePath,"rb");
	if(!pFile)
	{
		printf("无法打开该程序！\n");
		return NULL;
	}

	//将指针调到文件末尾
	fseek(pFile,0,SEEK_END);
	//读取文件大小
	fileSize = ftell(pFile);
	printf("文件大小:0x%X  %dKB",fileSize,fileSize/1024);

	//将指针调到文件开头
	fseek(pFile,0,SEEK_SET);
	//分配缓存区
	pFileBuffer = malloc(fileSize);
	if(!pFileBuffer)
	{
		printf("内存分配失败！");
		free(pFileBuffer);
		pFileBuffer = NULL;
		fclose(pFile);
		return NULL;
	}
	size_t flag = fread(pFileBuffer,fileSize,1,pFile);
	if(!flag)
	{
		printf("数据读取失败！");
		free(pFileBuffer);
		pFileBuffer = NULL;
		fclose(pFile);
		return NULL;
	}
	
	//读取成功后关闭文件
	fclose(pFile);
	return pFileBuffer;
}

//把文件缓冲 读取到 镜像缓冲区中
//参数：文件指针、镜像大小、头大小、DOS头指针、节数、节指针
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,DWORD SizeOfImage,DWORD SizeOfHeaders,PIMAGE_DOS_HEADER pDOSHeader,DWORD NumberOfSection,PIMAGE_SECTION_HEADER pSectionHeader,OUT LPVOID* pImage)
{
	LPVOID pImageBuffer = malloc(SizeOfImage);
	//根据镜像大小分配空间
	if(!pImageBuffer)
	{
		printf("内存分配失败！");
		return 0;
	}
	//初始化缓冲区,从头开始赋0
	memset(pImageBuffer,0,SizeOfImage); 
	//先把头放入缓存区中
	memcpy(pImageBuffer,pDOSHeader,SizeOfHeaders);
	//根据节表多少，循环录入，从磁盘中节开始的地方加上磁盘中对齐后的大小
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

	
	//截取路径最后面的文件名

	char file_name[50];

	pFileBuffer = readPEFile(f);
	if(!pFileBuffer)
	{
		printf("无法打开该程序！\n");
		return ;
	}

	//判断是否有MZ标志
	if(*(PWORD)pFileBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("0x%X\n",*(PWORD)pFileBuffer);
		printf("不存在MZ标识，请确认打开的文件是否为.exe .dll .sys文件");
		//释放堆内存	
		free(pFileBuffer);
		pFileBuffer = NULL;
		return ;
	}

	printf("\n\n");

	pDOSHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	printf("=======================<<DOS头>>=======================\n");
	printf("MZ标识: %c%c\n",pDOSHeader ->e_magic,*((char*)pFileBuffer+1));
	printf("PE偏移: 0x%X\n",pDOSHeader ->e_lfanew);
	if(*((PWORD)((DWORD)pFileBuffer+pDOSHeader ->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不存在PE标识,文件可能已损坏");
		//释放堆内存	
		free(pFileBuffer);
		pFileBuffer = NULL;
		return ;
	}

	pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDOSHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeaders)+4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	int HeaderSize = pOptionHeader ->SizeOfHeaders;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

	//打印NT头
	printf("=======================<<NT头>>=======================\n");
	printf("NT头: %c%c\n",pNTHeaders ->Signature,*((char*)(pDOSHeader ->e_lfanew+(DWORD)pFileBuffer+1)));
	printf("=======================<<PE头>>=======================\n");
	printf("节的数量: %d\n",pPEHeader ->NumberOfSections);
	printf("文件生成时间: ");
	tansformTimeStamp(pPEHeader->TimeDateStamp);
	printf("可选PE头大小: 0x%X\n",pPEHeader ->SizeOfOptionalHeader);
	
	if(((pPEHeader ->Characteristics) & 0x8000) > 0x8000){
		printf("Characteristics: 0x%X\n文件中不存在重定义信息,该文件存在IAT表\n",pPEHeader->Characteristics);
	}else{
		printf("Characteristics: 0x%X\n",pPEHeader->Characteristics);
	}
	
	printf("=======================<<可选PE头>>=======================\n");
	if(pOptionHeader->Magic == 0x20b)
	{printf("可选PE头: 0x%X   该文件是32位下的PE文件\n",pOptionHeader ->Magic);}
	else if(pOptionHeader->Magic == 0x10b)
	{printf("可选PE头: 0x%X   该文件是64位下的PE文件\n",pOptionHeader ->Magic);}
	else{
		printf("可选PE头: 0x%X   该文件是ROM镜像\n",pOptionHeader ->Magic);
	}
	printf("镜像基址: 0x%X\n",pOptionHeader ->ImageBase);
	printf("OEP(RVA): 0x%X\n",pOptionHeader ->AddressOfEntryPoint);
	printf("OEP(FOA): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->AddressOfEntryPoint));
	printf("内存节对齐: 0x%X\n",pOptionHeader ->SectionAlignment);
	printf("磁盘节对齐: 0x%X\n",pOptionHeader ->FileAlignment);
	if(((pOptionHeader ->SizeOfImage)/1024) > 1){
		printf("内存镜像大小: 0x%X %dMB %dKB\n",pOptionHeader ->SizeOfImage,(pOptionHeader ->SizeOfImage)/1024/1024,(pOptionHeader ->SizeOfImage)/1024%1024);
	}else{
		printf("内存镜像大小: 0x%X %dMB%dKB\n",pOptionHeader ->SizeOfImage,(pOptionHeader ->SizeOfImage)/1024);
	}
	printf("头大小: 0x%X %dKB\n",pOptionHeader ->SizeOfHeaders,(pOptionHeader ->SizeOfHeaders)/1024);
	if(((pOptionHeader ->CheckSum)/1024) > 1){
		printf("校验和: 0x%X %dMB %dKB\n",pOptionHeader ->CheckSum,(pOptionHeader ->CheckSum)/1024/1024,(pOptionHeader ->CheckSum)/1024%1024);
	}else{
		printf("校验和: 0x%X %dKB\n",pOptionHeader ->CheckSum,(pOptionHeader ->CheckSum)/1024);
	}

	

	printf("=====================表信息=====================\n\n");
	for(int i=0;i<15;i++)
	{
		printf("================================\n\n");
		switch(i)
		{
			case 0:
				printf("导出表信息: \n");
				break;
			case 1:
				printf("注: 如若函数名开头以?开头，说明该函数名已被粉碎过，即没有使用extern 'C'导出或使用了重载\n\n");
				printf("导入表信息: \n");
				break;
			case 2:
				printf("资源表信息: \n");
				break;
			case 3:
				printf("异常表信息: \n");
				break;
			case 4:
				printf("安全证书信息: \n");
				break;
			case 5:
				printf("重定位表信息: \n");
				break;
			case 6:
				printf("调试表信息: \n");
				break;
			case 7:
				printf("版权表信息: \n");
				break;
			case 8:
				printf("全局指针表信息: \n");
				break;
			case 9:
				printf("TLS表信息: \n");
				break;
			case 10:
				printf("加载配置表信息: \n");
				break;
			case 11:
				printf("绑定导入表信息: \n");
				break;
			case 12:
				printf("IAT表信息: \n");
				break;
			case 13:
				printf("延迟导入表信息: \n");
				break;
			case 14:
				printf("COM信息表: \n");
				break;
		}
		if(i == 4){
			printf("FOA:                  0x%X\n",pOptionHeader ->DataDirectory[i].VirtualAddress);
			printf("Size:                 0x%X\n\n",pOptionHeader ->DataDirectory[i].Size);
		}else{
			//这里的pSectionHeader的位置是 节表偏移位置+pFileBuffer
			printf("FOV(未包含ImageBase): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[i].VirtualAddress));
			printf("VirtualAddress:       0x%X\n",pOptionHeader ->DataDirectory[i].VirtualAddress);
			printf("Size:                 0x%X\n\n",pOptionHeader ->DataDirectory[i].Size);
		}

		//导出表
		if(i==0)
		{	
			if((pOptionHeader ->DataDirectory[0].VirtualAddress) == 0x1000) printf("该文件不包含导出表\n\n");
			//如果导出表存在就打印导出表
			if((pOptionHeader ->DataDirectory[0].VirtualAddress) != 0 && (pOptionHeader ->DataDirectory[0].VirtualAddress) != 0x1000)
			{
				//把磁盘中表的位置赋值给指针
				pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[0].VirtualAddress)));
				pName = (char*)((pExportTable->Name + (DWORD)pFileBuffer)+1);

				//printf("pName: 0x%X\n",pName);
				//printf("fileSize: 0x%X\n",fileSize);
				//得分三种情况
				//①名字地址大于文件大小，且名字地址的FOV小于文件大小
				//②名字地址小于文件大小
				//③名字地址大于文件大小
				if(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name)< fileSize)
				{
					pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name) + (DWORD)pFileBuffer );
					printf("导出表名字:              ");

					while(*(pName)!=0)
					{
						printf("%c",*pName);
						pName++;
					}

					printf("\n");
				}else{printf("导出表信息有误！\n\n");}

				//释放指针
				pName=NULL;

				printf("导出表名字所在地址:      0x%X\n",pExportTable->Name);
				printf("导出表名字所在地址(FOV): 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->Name));
				printf("序号基数: 0x%X\n",pExportTable->Base);
				printf("函数个数: %d\n",pExportTable->NumberOfFunctions);
				printf("非匿名函数个数: %d\n\n",pExportTable->NumberOfNames);
				printf("函数表RVA: 0x%X\n",pExportTable->AddressOfFunctions);
				printf("函数表FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfFunctions));
				printf("名称表RVA: 0x%X\n",pExportTable->AddressOfNames);
				printf("名称表FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNames));
				printf("序号表RVA: 0x%X\n",pExportTable->AddressOfNameOrdinals);
				printf("序号表FOA: 0x%X\n\n",RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNameOrdinals));

				

				functionName = (int*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNames)));
				
				functionAddress = (int*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfFunctions)));
				int* tempFunctionName = functionName;

				//遍历函数地址表
				for(int i=0;i<pExportTable->NumberOfFunctions;i++)
				{
					orderAddress = (short*)((DWORD)pFileBuffer+(RVAToFOA(pSectionHeader,HeaderSize,pExportTable->AddressOfNameOrdinals)));
					printf("索引:%d",i);
					printf("  函数地址: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*functionAddress));

					//匹配序号表
					for(int j=0;j<pExportTable->NumberOfNames;j++)
					{
						if(i==(*orderAddress))
						{
							printf("  导出序号: @%d",(*orderAddress)+pExportTable->Base);
							break;
						}else{
							orderAddress++;
						}
					}

					//匹配函数名称表
					for(int k=0;k<pExportTable->NumberOfNames;k++)
					{
						if((*orderAddress)==k)
						{
							//printf("  functionName(RVA): 0x%X",*functionName);
							if(RVAToFOA(pSectionHeader,HeaderSize,*functionName) < fileSize)
							{		
								
								printf("  函数名: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*functionName));
								pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,*functionName) + (DWORD)pFileBuffer);
								printf("  函数名: ");

								while(*(pName)!=0)
								{
									printf("%c",*pName);
									pName++;
								}

								printf("\n\n");
							}else{printf("   函数名称表信息有误！\n\n");}

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


		//导入表
		if(i==1)
		{
			//如果导出表存在就打印导入表
			if((pOptionHeader ->DataDirectory[1].VirtualAddress) != 0)
			{
				//把磁盘中表的位置赋值给指针
				pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[1].VirtualAddress)));
				pName = (char*)(pImportTable->Name + (DWORD)pFileBuffer);
				UINT hexNum = 0x80000000;
				

				//遍历多张导入表
				while((pImportTable ->OriginalFirstThunk)!=0)
				{
					int sum = 1;
					int* pThunk = (int*)(RVAToFOA(pSectionHeader,HeaderSize,pImportTable->OriginalFirstThunk) + (DWORD)pFileBuffer);
					char* pFunctionName = (char*)((RVAToFOA(pSectionHeader,HeaderSize,*pThunk) + (DWORD)pFileBuffer) + 2);

					
					//输出导入表名字
					if(RVAToFOA(pSectionHeader,HeaderSize,pImportTable->Name)< fileSize)
					{
						pName = (char*)( RVAToFOA(pSectionHeader,HeaderSize,pImportTable->Name) + (DWORD)pFileBuffer );
						printf("导入表名字:      ");

						while(*(pName)!=0)
						{
							printf("%c",*pName);
							pName++;
						}

						printf("\n");
					}else{printf("导入表信息有误！\n\n");}

					//释放指针
					pName=NULL;

					printf("导入表地址:      0x%X\n",(int)pImportTable-(int)pFileBuffer);
					printf("INT表地址:       0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pImportTable->OriginalFirstThunk));
					printf("IAT表地址:       0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pImportTable->FirstThunk));
					printf("时间戳: %d",pImportTable->TimeDateStamp);
					if(pImportTable->TimeDateStamp == 0){printf("        该dll未绑定，即IAT表的值为非地址\n\n");}
					else{printf("        该 dll 已绑定，IAT表内包含地址值\n\n");}

					//遍历INT表
					while(*pThunk!=0)
					{
						printf("序号: %d",sum);
						
						//如果开头为1，输出序号
						if((*pThunk) >= hexNum)
						{
							//取后面31位的值
							*pThunk = (*pThunk)& 0x0FFF;
							printf("   函数序号: 0x%X  %d",*pThunk,*pThunk);
						}else
						{
							//如果开头为0，输出名字
							printf("   函数名地址: 0x%X",*pThunk +2);
							printf("   函数名文件中地址: 0x%X",RVAToFOA(pSectionHeader,HeaderSize,*pThunk) +2);
							printf("   函数名称: ");
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


		//资源表
		if(i==2)
		{
			int entryNum;
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry;
			int idTable[23]= {1,2,3,4,5,6,7,8,9,10,11,12,14,16,17,19,20,21,22,23,24};
			char* resTypeMean[23] ={ "鼠标指针", "位图", "图标", "菜单", "对话框", "字符串列表","字体目录", "字体", "快捷键", "非格式化资源", "消息列表",
									"鼠标指针组", "图标组","版本信息","与.rc关联的头文件","即插即用资源","VXD","动画游标","动画图标","HTML 资源","并行程序集清单"};	//windows已定义类型
			char* resTypeName[23]={"RT_CURSOR","RT_BITMAP","RT_ICON","RT_MENU","RT_DIALOG","RT_STRING","RT_FONTDIR","RT_FONT","RT_ACCELERATOR","RT_RCDATA","RT_MESSAGETABLE",
									"RT_GROUP_CURSOR","RT_GROUP_ICON","RT_VERSION","RT_DLGINCLUDE","RT_PLUGPLAY","RT_VXD","RT_ANICURSOR","RT_ANIICON","RT_HTML","RT_MANIFEST"};


			//如果导出表存在就打印导入表
			if((pOptionHeader ->DataDirectory[2].VirtualAddress) != 0)
			{
				pResourceTable = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[2].VirtualAddress)));
				//获取资源项的数量
				entryNum = pResourceTable->NumberOfIdEntries + pResourceTable->NumberOfNamedEntries;

				//定位资源项起始地点
				 pEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTable+1);
				 
				 if(entryNum < 1000){
					 printf("编号项数: %1d  字符串项数: %1d\n第一层资源目录起始地址:   0x%X \n",pResourceTable->NumberOfIdEntries,pResourceTable->NumberOfNamedEntries,(DWORD)pResourceTable-(DWORD)pFileBuffer);	
					 printf("资源项(类别)起始地址:0x%X\n\n",(DWORD)pEntry-(DWORD)pFileBuffer);	

					 //判断是不是exe文件
					 if(strstr(f,"exe")!=NULL){

						 //编号 类型 [discardble] 文件地址    discardble代表可以在不用该资源时卸载掉
						 //1001 icon  "icon.ico"
						 //TITLE_ICON icon "cover.ico"

						 //第一层
						 //遍历资源项(类别)
						 for(int i=0;i<entryNum;i++){

							 if(!pEntry[i].NameIsString) //如果NameIsString为0，即Name首位为0,后31为对应的就是类型id		是Windows预先定义过的类型
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
											 printf("自定义资源类型的id: %d\n",pEntry[i].Id );	
											 break;
										 }

									 }
								 }


							 }else{

								 //如果NameIsString为1，说明联合体是Name，那他的低31就是偏移，偏移加资源表起始地址指向一个Unicode结构体		 是一个自定义类型名称
								 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable+pEntry[i].NameOffset);
								 WCHAR typeName[20];
								 memcpy_s(typeName,20,pUnicodeString->NameString,pUnicodeString->Length*sizeof(WCHAR));
								 printf("类型名称:%ls\n",typeName);	
							 }

							 //第二层
							 //遍历资源项(唯一编号)
							 if(pEntry[i].DataIsDirectory){  //如果DataIsDirectory是1，代表联合体是rDirectory,指向下一个结构目录的首地址  第一层，第二层的这个值默认为1

								 PIMAGE_RESOURCE_DIRECTORY pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceTable + pEntry[i].OffsetToDirectory);
								 PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir+1);
								 int entryNum2 = pResourceDir->NumberOfIdEntries+pResourceDir->NumberOfNamedEntries;


								 printf(" |\n");	
								 printf("  --第二层资源目录起始地址:   0x%X\n",(DWORD)pResourceDir-(DWORD)pFileBuffer);	
								 printf("    资源项(唯一编号)起始地址: 0x%X\n",(DWORD)pEntry2 - (DWORD)pFileBuffer);
								 printf("    编号项数: %1d  字符串项数:  %1d\n\n",pResourceDir->NumberOfIdEntries,pResourceDir->NumberOfNamedEntries);	

								 //遍历资源项
								 for(int k=0;k<entryNum2;k++){
									 if(!pEntry2[k].NameIsString){
										 printf("    id: %d\n",pEntry2[k].Id);	
									 }else{

										 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable + (pEntry2[k].NameOffset));
										 WCHAR idName[20];
										 memcpy(idName,pUnicodeString->NameString,(pUnicodeString->Length)*sizeof(WCHAR));
										 printf("    自定义资源: %s\n",idName);	

									 }

									 //第三层
									 //遍历资源项(代码页即所用语言)
									 if(pEntry2[k].DataIsDirectory){
										 PIMAGE_RESOURCE_DIRECTORY pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceTable + pEntry2[k].OffsetToDirectory);
										 PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2+1);
										 int entryNum3 = pResourceDir2->NumberOfIdEntries+pResourceDir2->NumberOfNamedEntries;

										 printf("     |\n");	
										 printf("      --第三层资源目录起始地址:  0x%X\n",(DWORD)pResourceDir2-(DWORD)pFileBuffer);	
										 printf("        资源项(代码页)起始地址:  0x%X\n",(DWORD)pEntry3 - (DWORD)pFileBuffer);
										 printf("        编号项数: %1d  字符串项数: %1d\n\n",pResourceDir2->NumberOfIdEntries,pResourceDir2->NumberOfNamedEntries);	

										 for(int t=0;t<entryNum3;t++){
											 if(!pEntry3[t].NameIsString){

												 switch(pEntry3[t].Id)
												 {
												 case 1025:
													 printf("        语言编号:    %d-阿拉伯语\n",pEntry3[t].Id);
													 break;
												 case 1028:
													 printf("        语言编号:    %d-中文繁体\n",pEntry3[t].Id);
													 break;
												 case 1033:
													 printf("        语言编号:    %d-英语\n",pEntry3[t].Id);
													 break;
												 case 1041:
													 printf("        语言编号:    %d-日语\n",pEntry3[t].Id);
													 break;
												 case 2052 :
													 printf("        语言编号:    %d-中文简体\n",pEntry3[t].Id);
													 break;
												 }

											 }else{

												 PIMAGE_RESOURCE_DIR_STRING_U pUnicodeString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceTable+pEntry3[t].NameOffset);
												 WCHAR languageName[20];
												 memcpy_s(languageName,20,pUnicodeString->NameString,pUnicodeString->Length*sizeof(WCHAR));
												 printf("        语言: %s",languageName);	

											 }

											 if(!pEntry3[t].DataIsDirectory){

												 PIMAGE_RESOURCE_DATA_ENTRY pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResourceTable+pEntry3[t].OffsetToData);
												 LPVOID pSourceBlock = (LPVOID)((DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,pResData->OffsetToData));

												 printf("        数据项地址:       0x%X\n",(DWORD)pSourceBlock-(DWORD)pFileBuffer);	
												 printf("        资源数据块的RVA:  0x%X\n",pResData->OffsetToData);	
												 printf("        资源数据块的FOA:  0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,pResData->OffsetToData));	
												 printf("        资源数据块的长度: 0x%X\n\n",pResData->Size);	

												 short* pFlag;

												 switch(pEntry[i].Id)
												 {
													 //case 3:
													 //如果图标起头是 89 50 4E 47 说明是png文件，直接在桌面上创建一个文件写入

												 case 4:
													 pFlag = (short*)((int)pSourceBlock + 4);
													 if(*pFlag == 0x10){
														 printf("        这是一个弹出菜单\n");	
													 }else if(*pFlag == 0){
														 printf("        这是一个普通菜单\n");	
													 }
													 break;
												 case 16:
													 LPVOID pVersion = (LPVOID)((int)pSourceBlock + 97);
													 //这个地址就是StringFileInfo的起始位置
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
					printf("该文件资源表不存在\n\n");	
				}
				 
			}
		
		}

		//安全证书信息
		if(i==4){

			if(((DWORD)pFileBuffer + pOptionHeader ->DataDirectory[4].VirtualAddress + pOptionHeader ->DataDirectory[4].Size) <= (DWORD)pFileBuffer + fileSize){
				pWinCertificate = (LPWIN_CERTIFICATE)((DWORD)pFileBuffer + pOptionHeader ->DataDirectory[4].VirtualAddress);
				printf("证书长度:             0x%X\n",pWinCertificate->dwLength);	
				printf("证书版本号:           0x%X\n",pWinCertificate->wRevision);	
				printf("证书类型:             0x%X\n\n",pWinCertificate->wCertificateType);	
				int length;

				//如果证书数据大小不为8的倍数,向上取8的倍数
				if((pWinCertificate->dwLength)%8 != 0){
					length = ((pWinCertificate->dwLength)-(pWinCertificate->dwLength%8))+8;
					if(length != pOptionHeader ->DataDirectory[4].Size){
						printf("证书已被破坏\n\n");	
					}
				}
			}else{
				printf("证书已被破坏\n\n");	
			}
		}

		//Ctrl + K + C 注释  Ctrl + K + U 取消注释

		//重定位表
		if(i==5)
		{
			printf("是否打印重定位表？");	
			if(getchar() == 'y'){
				short* pOffset = NULL;
				pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[5].VirtualAddress));
				int count = 0;
				while(pReloc->VirtualAddress != 0)
				{	
					count++;
					pOffset = (short*)((int)pReloc + 8);
					printf("第%d张重定位表的起始虚拟地址: 0x%X\n",count,pReloc->VirtualAddress);
					printf("第%d张重定位表的起始文件地址: 0x%X\n",count, RVAToFOA(pSectionHeader,HeaderSize,pReloc->VirtualAddress));
					printf("第%d张重定位表的大小: 0x%X\n",count,pReloc->SizeOfBlock);
					printf("偏移数量: %d\n\n",((pReloc->SizeOfBlock)-8)/2);

					printf("以下为需要重定位的地址 的偏移地址和在文件中的地址\n");
					printf("文件中的偏移地址处以及后面3个字节就是需要被修改的绝对地址\n\n");
					for(int i=0;i<(((pReloc->SizeOfBlock)-8)/2);i++)
					{
						//printf("偏移值: 0x%X 0x%X\n",*pOffset,*pOffset>>12);
						if(*pOffset!=0 && (*pOffset>>12) == 0x3)
						{
							printf("偏移地址: 0x%X \t文件中的偏移地址：0x%X\n",(pReloc->VirtualAddress) + (*pOffset & 0x0fff),RVAToFOA(pSectionHeader,HeaderSize,((pReloc->VirtualAddress) + (*pOffset & 0x0fff))));
							pOffset++;
						}else if(*pOffset!=0 && (*pOffset>>12) == 0x0){
							printf("无需修改的偏移: 0x%X\n",(pReloc->VirtualAddress) + *pOffset);
						}else{
							printf("仅作对齐: 0x%X\n",*pOffset);
						}
					}
					printf("\n",((pReloc->SizeOfBlock)-8)/2);
					pReloc = (PIMAGE_BASE_RELOCATION)((int)pReloc + pReloc->SizeOfBlock);
				}
			}
		}


		//导入绑定表
		if(i==11)
		{	
			int sum = 0;
			PIMAGE_BOUND_IMPORT_DESCRIPTOR pTemImportBondTable = NULL;
			if((pOptionHeader ->DataDirectory[11].VirtualAddress) != 0)
			{
		
				pImportBondTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (RVAToFOA(pSectionHeader,HeaderSize,pOptionHeader ->DataDirectory[11].VirtualAddress)));

				
				//遍历绑定导入表
				while(pImportBondTable->TimeDateStamp != 0)
				{
					sum++;
					printf("个数: %d\n",sum);

					pTemImportBondTable = pImportBondTable;

					//输出DLL名字
					if(RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName))< fileSize)
					{
						pName = (char*)( (DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName)) );
						printf("DLL名字: ");

						while(*(pName)!=0)
						{
							printf("%c",*pName);
							pName++;
						}

						printf("\n");
					}else{printf("绑定导入表信息有误！\n\n");}

					//释放指针
					pName=NULL;


					printf("DLL名称地址(FOV): 0x%X\n",RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pImportBondTable->OffsetModuleName) ) );
					printf("文件生成时间:");
					tansformTimeStamp(pImportBondTable->TimeDateStamp);
					printf("DLL中绑定的DLL数量：%d\n\n",pImportBondTable->NumberOfModuleForwarderRefs);


					for(int i=0;i<pImportBondTable->NumberOfModuleForwarderRefs;i++)
					{
						pTemImportBondTable++;
						pBondRef = (PIMAGE_BOUND_FORWARDER_REF)pImportBondTable;
					
						//输出DLL中的DLL信息
						if(RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pBondRef->OffsetModuleName))< fileSize)
						{
							printf("以下是DLL中所绑定的DLL信息: \n");
							printf("------------------------------ \n");
							pName = (char*)( (DWORD)pFileBuffer + RVAToFOA(pSectionHeader,HeaderSize,((pOptionHeader ->DataDirectory[11].VirtualAddress) + pBondRef->OffsetModuleName)) );
							printf("DLL名字: ");

							while(*(pName)!=0)
							{
								printf("%c",*pName);
								pName++;
							}

							printf("\n");
						}else{printf("绑定导入表中Ref表信息有误！\n\n");}

						printf("文件生成时间:");
						tansformTimeStamp(pBondRef ->TimeDateStamp);

					}

					printf("**************************\n\n");
					//如果DLL中还包含DLL，那么下一个绑定导入表的位置就是一开始绑定导入表的位置加上衍生DLL的个数
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
	
	printf("=======================<<节表>>=======================\n");
	while(pSectionHeader->Characteristics != 0 && (sectionNum<(pPEHeader ->NumberOfSections))){
		
	printf("\n");
		sectionNum++;
		printf("=========节%d=========\n\n",sectionNum);

		char snBuffer[8];
		memcpy(snBuffer,(void*)((int)pFileBuffer+sectionStartingPosition),8);
		printf("节名: %s\n",snBuffer);
		
		if(strcmp(snBuffer,".text")==0){
			printf("代码节\n");	
		}else if(strcmp(snBuffer,".rdata")==0){
			printf("导入表节\n");
		}else if(strcmp(snBuffer,".data")==0){
			printf("数据节\n");
		}else if(strcmp(snBuffer,".rsrc")==0){
			printf("资源表节\n");
		}else if(strcmp(snBuffer,".reloc")==0){
			printf("重定位表节\n");
		}else if(strcmp(snBuffer,".tls")==0){
			printf("线程本地存储表节\n");
		}else if(strcmp(snBuffer,".edata")==0){
			printf("导出数据节\n");
		}else if(strcmp(snBuffer,".idata")==0){
			printf("导入数据节\n");
		}else if(strcmp(snBuffer,".pdata")==0){
			printf("异常表数据节\n");
		}else{
			printf("未知节\n");
		}

		printf("\n");
		printf("节表的起始位置: 0x%X\n",sectionStartingPosition);
		printf("节的实际大小: 0x%X\n",pSectionHeader ->Misc.VirtualSize);
		printf("该节在内存中的偏移地址(算上镜像基址): 0x%X\n",pOptionHeader->ImageBase+pSectionHeader ->VirtualAddress);
		printf("该节在内存中的偏移地址: 0x%X\n",pSectionHeader ->VirtualAddress);
		printf("该节在磁盘中的偏移地址: 0x%X\n",pSectionHeader ->PointerToRawData);
		printf("该节在磁盘中对齐后的大小: 0x%X\n",pSectionHeader ->SizeOfRawData);
		printf("该节在磁盘中结束位置: 0x%X\n",(pSectionHeader ->PointerToRawData + pSectionHeader ->SizeOfRawData)-16);
		printf("\n");
		printf("该节特点：\n");

		//倒数第二位
		long long int symbol = (pSectionHeader ->Characteristics)| 0xFFFFFF00;
		symbol = symbol - 0xFFFFFF00;
		symbol = symbol>>4;

		switch(symbol)
		{
			case 2:
				printf("该节包含可执行代码\n");
				break;
			case 4:
				printf("该节包含已初始化数据\n");
				break;
			case 6:
				printf("该节包含可执行代码和已初始化数据\n");
				break;
			case 8:
				printf("该节包含未初始化数据\n");
				break;
			case 0xA:
				printf("该节包含可执行代码和未初始化数据\n");
				break;
			case 0xC:
				printf("该节包含已初始化数据和未初始化数据\n");
				break;
			case 0xE:
				printf("该节包含已初始化数据和未初始化数据以及可执行代码\n");
				break;
		}

		//最高位
		long long int first = (pSectionHeader ->Characteristics)>>28;
		if(first==1){printf("该节未共享\n");}
		else if(first==2){printf("该节可执行\n\n");}
		else if(first==4){printf("该节可读\n\n");}
		else if(first==6){printf("该节可读可执行\n\n");}
		else if(first==8){printf("该节可写\n\n");}
		else if(first==0xA){printf("该节可写可执行\n\n");}
		else if(first==0xC){printf("该节可读可写\n\n");}
		else if(first==0xE){printf("该节可读可写可执行\n\n");}
		else{ ;}	
		pSectionHeader = (PIMAGE_SECTION_HEADER)((int)pSectionHeader + 40);
		sectionStartingPosition = sectionStartingPosition + 40;
		printf("====================\n\n");
	}
	printf("总节数：%d\n",sectionNum);
	free(pFileBuffer);
	pFileBuffer = NULL;
}



int _tmain(int argc, _TCHAR* argv[])
{
	printf("请输入文件路径: \n");
	while(gets(f) != NULL){
		replace(f,"\""," ");
		trim(f);

		printHeaders();
		system("pause");

		system("Cls");
		printf("请输入文件路径: \n");
	}
	
}




//头大小小于内存对齐时，节就从 内存对齐大小开始
//当头大小超过内存对齐时，用头大小%内存大小，(结果+1)*内存大小）
//接下来判断Misc，Misc的值的大小是否超过内存对齐，接下来干的和上面一样
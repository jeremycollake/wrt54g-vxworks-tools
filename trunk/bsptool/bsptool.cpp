//
// bsptool.cpp : (c)2006 Jeremy Collake <jeremy@bitsum.com>
// http://www.bitsum.com 
// 
// This code can be built under Windows (msvc++) or linux (g++).
//
//

#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DEBUG
#define NDEBUG
#endif

#include <assert.h>

// for gcc/g++
#ifndef WIN32
#define _strcmpi strcasecmp
#endif

//todo: adjust these to right types for all systems
// our sanity check will let us know at runtime
// if these are wrong. was too lazy to look up
// linux bit size specific types.
#ifndef __int8
#define __int8 char
#endif

#ifndef __int32
#define __int32 long
#endif

#ifndef __int16
#define __int16 short
#endif

#ifndef BYTE
#ifndef UNICODE
#define SBYTE char
#define BYTE unsigned char
#else
#define SBYTE __int8
#define BYTE unsigned __int8
#endif
#endif

#define BOOTP_MAC_ADDR_SIZE 6

#pragma pack(push, 1)

#define BOOTP_SIZE 0x400 // size above should be if its defined right (we verify it is)
#define WRT54G_CODE_PATTERN 'WGV5'  
#define WRT54GS_CODE_PATTERN 'WGV5'  // yea, both are the same
#define MAC_STRING_SIZE 17
#define INVALID_CONFIG_VALUE 0  //todo: if zero is a valid config, must use some other marker

///////////////////////////////////////////////////////////
// BOOTP pre-requisities
//
typedef struct _MY_MAC_ADDR
{
	unsigned __int8 addr[6]; // big endian
} MY_MAC_ADDR, *PMY_MAC_ADDR;

////////////////////////////////////////////////////////////
// VxWorks BSP BOOTP definition
// by Jeremy Collake <jeremy@bitsum.com>
// WARNING: This is not an official definition.
//
typedef struct _BOOTP_BLOCK
{
	unsigned __int32 dwCodePattern;
	unsigned __int16 wChecksum;
	unsigned __int16 wUnknown0;
	unsigned __int32 dwBootcodeVersion;
	SBYTE szDevice[0x40];
	SBYTE szVendor[0x40];
	SBYTE szCountry[0x20];
	SBYTE szSerial[0x20];
	unsigned __int8 VersionMajor;
	unsigned __int8 VersionMinor;
	unsigned __int16 wpciid; 
	unsigned __int32 dwConfig;
	_MY_MAC_ADDR macAddr1;
	_MY_MAC_ADDR macAddr2;
	_MY_MAC_ADDR macAddr4; /* dunno if this really is a mac */
	_MY_MAC_ADDR macAddr3;
	SBYTE cUnknown3[0x12]; 
	SBYTE szBootString[770];
} BOOTP_BLOCK, *PBOOTP_BLOCK;
#pragma pack(pop)

/* boot string flags:

   0x02  - load local system symbols
   0x04  - don't autoboot
   0x08  - quick autoboot (no countdown)
   0x20  - disable login security
   0x40  - use bootp to get boot parameters
   0x80  - use tftp to get boot image
   0x100 - use proxy arp
   */

unsigned __int16 bootp_checksum(BOOTP_BLOCK *pbootp)
{
	unsigned __int16 nSum=0;
	unsigned char *p1=(unsigned char *)pbootp;
	unsigned __int16 nOldchecksum=pbootp->wChecksum;
	pbootp->wChecksum=0xffff; 
	for(int nI=0;nI<sizeof(BOOTP_BLOCK);nI++,p1++)
	{
		nSum+=*p1;		
	}
	pbootp->wChecksum=nOldchecksum;
	return nSum+2; // not sure where the +2 is coming from..
}

#define strcpy_x(p1,p2) if(p1 && p2) strcpy(p1,p2)

bool SanityChecks()
{
	if(sizeof(BOOTP_BLOCK)!=BOOTP_SIZE || sizeof(MY_MAC_ADDR)!=BOOTP_MAC_ADDR_SIZE)
	{
		printf(" bootp size:    %d\n", sizeof(BOOTP_BLOCK));
		printf(" mac addr size: %d\n", sizeof(MY_MAC_ADDR));
		return false;
	}
	return true;
}

void ShowUsage()
{
	printf("\n"
		" Usage:\n"
		"    bsptool [/v] imagefile [/mac1 x] [/mac2 x] [/mac2 x] [/serial x] "
		"			[/country x] [/vendor x] [/device x] [/codep x]\n"
		"\n"
		"    /v                     view only\n"
		"    /mac1 xx-xx-xx-xx-xx   1st MAC address\n"
		"    /mac2 xx-xx-xx-xx-xx   2nd MAC address (should be mac1+2)\n"
		"    /mac3 xx-xx-xx-xx-xx   3rd MAC address (should be mac1+3)\n"
		"    /serial xxxxxxxxxxxx   twelve digit serial number\n"		
		"    /device                optional device id (WRT54G or WRT54GS)\n"
		"    /country               optional country (i.e. US)\n"
		"    /vendor                optional vendor (i.e. LINKSYS)\n"
		"    /codep                 optional code pattern (WG54))\n"
		"    /bootstr               optional boot string\n"
		"    /config                optional config\n"
		"    imagefile              any image with BOOTP at end\n"
		"\n"		
		" Notes:\n"
		"\n"
		"    Any and all bootp parameters can be omitted.\n"
		"    Only one image file is supported per execution.\n"
		"    When /v (view only) is supplied, no changes will be made.\n"		
		"\n");
}

bool VerifyMAC(char *pszMac)
{		
	if(!pszMac) return false;
	size_t nLen=strlen(pszMac);
	if(nLen!=MAC_STRING_SIZE) return false;
	for(size_t nI=2;nI<nLen;nI+=3)
	{
		if(pszMac[nI]!=':' && pszMac[nI]!='-')
		{
			return false;
		}		
	}
	return true;
}

char *mac_to_sz(MY_MAC_ADDR *pMac, char *pszMac)
{
	pszMac[0]=0;
	for(int nI=0;nI<sizeof(MY_MAC_ADDR);nI++)
	{
		if(nI>0 && nI!=sizeof(MY_MAC_ADDR))
		{
			strcat(pszMac,"-");
		}
		char szFormatted[4];
		sprintf(szFormatted,"%02x",pMac->addr[nI]);
		strcat(pszMac,szFormatted);
	}	
	assert(VerifyMAC(pszMac));
	return pszMac;
}

MY_MAC_ADDR *sz_to_mac(char *pszMac, MY_MAC_ADDR *pMac)
{
	if(!VerifyMAC(pszMac)) return NULL;
	size_t nLen=strlen(pszMac);
	if(nLen!=MAC_STRING_SIZE) return false;	
	for(size_t nI=0,nMacIdx=0;nI<nLen && nMacIdx<sizeof(MY_MAC_ADDR);nI+=2)
	{
		if((pszMac[nI]<'a' || pszMac[nI]>'z') 
			&& 
			(pszMac[nI]<'A' || pszMac[nI]>'Z')
			&&
			(pszMac[nI]<'0' || pszMac[nI]>'9'))
		{
			// assumed seperator, skip
			nI--;
			continue;
		}

		char szNum[8];		
		unsigned int nNum=0;		
		szNum[0]=pszMac[nI];
		szNum[1]=pszMac[nI+1];
		szNum[2]=0;		
		sscanf(szNum,"%x",&nNum);		
		assert(!(nNum&0xffffff00));		
		pMac->addr[nMacIdx]=nNum;
		nMacIdx++;
	}	
	return pMac;
}

bool ViewBootp(char *pszFile)
{
	FILE *fIn;
	fIn=fopen(pszFile,"rb");
	if(!fIn) return false;
	fseek(fIn,0,SEEK_END);
	size_t nSize=ftell(fIn);
	if(nSize<BOOTP_SIZE) return false;
	fseek(fIn,(unsigned long)nSize-BOOTP_SIZE,SEEK_SET);
	
	BOOTP_BLOCK bootp;
	if(!fread(&bootp,1,BOOTP_SIZE,fIn)) 
	{
		printf(" ! ERROR: file i/o.\n");
		fclose(fIn);
		return false;
	}
	
	if(bootp.dwCodePattern!=WRT54G_CODE_PATTERN)
	{
		printf(" ! ERROR: Unknown code pattern in BOOTP block.\n");
		return false;
	}

	char szMac1[MAC_STRING_SIZE+1];
	char szMac2[MAC_STRING_SIZE+1];

	printf("\n"
		"BOOTP block\n"
		" codep        : 0x%04x\n"
		" checksum     : 0x%02x (calculated: 0x%02x)\n"		
		" bootcode ver : 0x%04x\n"		
		" model        : %s\n"
		" vendor       : %s\n"
		" country      : %s\n"
		" serial #     : %s\n"		
		" hardware ver : %d.%d\n"
		" pciid        : 0x%x\n"
		" config       : 0x%x\n"
		" mac1         : %s\n"
		" mac2         : %s\n"
		" boot string  : %s\n",
		bootp.dwCodePattern,		
		bootp.wChecksum,
		bootp_checksum(&bootp),
		bootp.dwBootcodeVersion,
		bootp.szDevice,
		bootp.szVendor,
		bootp.szCountry,
		bootp.szSerial,		
		bootp.VersionMajor,
		bootp.VersionMinor,
		bootp.wpciid,
		bootp.dwConfig,
		mac_to_sz(&bootp.macAddr1,szMac1),
		mac_to_sz(&bootp.macAddr2,szMac2),		
		bootp.szBootString);

	fclose(fIn);
	return true;
}

bool EmbedBootp(char *pszFile, BOOTP_BLOCK *pNewBootp)
{	
	FILE *fIn;
	fIn=fopen(pszFile,"r+b");
	if(!fIn) return false;
	fseek(fIn,0,SEEK_END);
	size_t nSize=ftell(fIn);
	if(nSize<BOOTP_SIZE) return false;
	fseek(fIn,(unsigned long)nSize-BOOTP_SIZE,SEEK_SET);
	BOOTP_BLOCK bootp;
	if(!fread(&bootp,1,BOOTP_SIZE,fIn)) 
	{
		printf(" ! ERROR: file i/o.\n");
		fclose(fIn);
		return false;
	}
	
	if(bootp.dwCodePattern!=WRT54G_CODE_PATTERN && bootp.dwCodePattern!=WRT54GS_CODE_PATTERN)
	{
		printf(" ! ERROR: Unknown code pattern in BOOTP block.\n");
		return false;
	}
	
	if(pNewBootp->dwCodePattern)
	{
		bootp.dwCodePattern=pNewBootp->dwCodePattern;	
	}
	if(pNewBootp->szDevice[0])
	{
		strcpy_x(bootp.szDevice,pNewBootp->szDevice);
	}
	if(pNewBootp->szCountry[0])
	{
		strcpy_x(bootp.szCountry,pNewBootp->szCountry);
	}
	if(pNewBootp->szVendor[0])
	{
		strcpy_x(bootp.szVendor,pNewBootp->szVendor);
	}
	if(pNewBootp->szBootString[0])
	{
		strcpy_x(bootp.szBootString,pNewBootp->szBootString);
	}
	if(pNewBootp->szSerial[0])
	{
		strcpy_x(bootp.szSerial,pNewBootp->szSerial);
	}
	if(pNewBootp->dwConfig!=INVALID_CONFIG_VALUE)
	{
		bootp.dwConfig=pNewBootp->dwConfig;
	}
	if(!(pNewBootp->macAddr1.addr[0]==0 && pNewBootp->macAddr1.addr[1]==0 &&
		pNewBootp->macAddr1.addr[2]==0 && pNewBootp->macAddr1.addr[3]==0 &&
		pNewBootp->macAddr1.addr[4]==0 && pNewBootp->macAddr1.addr[5]==0))  
	{
		memcpy(&bootp.macAddr1,&pNewBootp->macAddr1,sizeof(MY_MAC_ADDR));		
	}
	if(!(pNewBootp->macAddr2.addr[0]==0 && pNewBootp->macAddr2.addr[1]==0 &&
		pNewBootp->macAddr2.addr[2]==0 && pNewBootp->macAddr2.addr[3]==0 &&
		pNewBootp->macAddr2.addr[4]==0 && pNewBootp->macAddr2.addr[5]==0))  
	{
		memcpy(&bootp.macAddr2,&pNewBootp->macAddr2,sizeof(MY_MAC_ADDR));		
	}
	if(!(pNewBootp->macAddr3.addr[0]==0 && pNewBootp->macAddr3.addr[1]==0 &&
		pNewBootp->macAddr3.addr[2]==0 && pNewBootp->macAddr3.addr[3]==0 &&
		pNewBootp->macAddr3.addr[4]==0 && pNewBootp->macAddr3.addr[5]==0))  
	{
		memcpy(&bootp.macAddr3,&pNewBootp->macAddr3,sizeof(MY_MAC_ADDR));		
	}
	bootp.wChecksum=bootp_checksum(&bootp);
	fseek(fIn,(unsigned long)nSize-BOOTP_SIZE,SEEK_SET);
	if(fwrite(&bootp, 1, sizeof(BOOTP_BLOCK), fIn)!=sizeof(BOOTP_BLOCK))
	{
		printf(" ! ERROR: Writing BOOTP block to disk.\n");
		fclose(fIn);
		return false;
	}
	fclose(fIn);
	return true;
}

int main(int argc, char * argv[])
{
	printf("\nbsptool v0.4 - (c)2006 Jeremy Collake - http://www.bitsum.com\n");	

	if(argc<2)
	{
		ShowUsage();
		return 1;
	}
	
	bool bViewOnly=false;
	char *pszImageFile=NULL;
	char *pszMac1=NULL;
	char *pszMac2=NULL;
	char *pszMac3=NULL;
	char *pszSerial=NULL;
	char *pszCodePattern=NULL;
	char *pszDevice=NULL;
	char *pszBootString=NULL;
	char *pszCountry=NULL;
	char *pszVendor=NULL;
	unsigned long dwConfig=INVALID_CONFIG_VALUE;

	for(int nI=1;nI<argc;nI++)
	{
		if(!_strcmpi(argv[nI],"/v"))
		{
			bViewOnly=true;
		}
		else if(!_strcmpi(argv[nI],"/mac1"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszMac1=argv[nI];
			printf(" MAC1 supplied: %s\n", pszMac1);
		}
		else if(!_strcmpi(argv[nI],"/mac2"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszMac2=argv[nI];
			printf(" MAC2 supplied: %s\n", pszMac2);
		}
		else if(!_strcmpi(argv[nI],"/mac3"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszMac3=argv[nI];
			printf(" MAC3 supplied: %s\n", pszMac3);
		}
		else if(!_strcmpi(argv[nI],"/serial"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszSerial=argv[nI];
			printf(" Serial supplied: %s\n", pszSerial);
		}
		else if(!_strcmpi(argv[nI],"/country"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszCountry=argv[nI];
			printf(" Country supplied: %s\n", pszCountry);
		}
		else if(!_strcmpi(argv[nI],"/vendor"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszVendor=argv[nI];
			printf(" Vendor supplied: %s\n", pszVendor);
		}
		else if(!_strcmpi(argv[nI],"/codep"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszCodePattern=argv[nI];
			printf(" Code pattern supplied: %s\n", pszCodePattern);
		}
		else if(!_strcmpi(argv[nI],"/device"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszDevice=argv[nI];
			printf(" Device name supplied: %s\n", pszDevice);
		}
		else if(!_strcmpi(argv[nI],"/bootstr"))
		{
			if(++nI>=argc)
			{
				break;
			}
			pszBootString=argv[nI];
			printf(" Boot string: %s\n", pszBootString);
		}
		else if(!_strcmpi(argv[nI],"/config"))
		{
			if(++nI>=argc)
			{
				break;
			}
			if(strstr(argv[nI],"0x") || strstr(argv[nI],"0X"))
			{
				sscanf(argv[nI]+strlen("0x"),"%x",&dwConfig);
			}
			else
			{
				dwConfig=atoi(argv[nI]);
			}
			printf(" Config: 0x%x\n", dwConfig);
		}
		else
		{
			if(pszImageFile) 
			{
				printf("! Warning: More the one image file specified or bad params.\n");
			}
			else
			{
				pszImageFile=argv[nI];
			}

		}
	}

	if(!pszImageFile
		||
		(!bViewOnly && ((pszMac1 && !VerifyMAC(pszMac1)) || (pszMac2 && !VerifyMAC(pszMac2)))))
	{
		printf("! Error: One or more parameters missing or incorrect.\n");
		ShowUsage();
		return 1;
	}

	if(!SanityChecks())
	{
		printf("! Error: Sanity checks failed.\n");
		return 1;
	}
	
	printf("\nViewing BOOTP block ...\n");
	if(!ViewBootp(pszImageFile))
	{
		printf("! ERROR: Viewing.\n");
		return 1;
	}
	if(bViewOnly)
	{
		printf("View done\n");
		return 0;
	}

	BOOTP_BLOCK bootp;
	memset(&bootp,0,sizeof(BOOTP_BLOCK)); // make sure everythinig initialized to zero
	
	if(pszCodePattern)
	{
		bootp.dwCodePattern=(unsigned long)atol(pszCodePattern);
	}
	bootp.dwConfig=dwConfig;
	strcpy_x(bootp.szDevice,pszDevice);
	strcpy_x(bootp.szVendor,pszVendor);
	strcpy_x(bootp.szCountry,pszCountry);
	strcpy_x(bootp.szBootString,pszBootString);
	strcpy_x(bootp.szSerial,pszSerial);
	MY_MAC_ADDR mac;
	if(pszMac1)
	{
		memcpy(&bootp.macAddr1,sz_to_mac(pszMac1,&mac),sizeof(mac));
	}
	if(pszMac2)
	{
		memcpy(&bootp.macAddr2,sz_to_mac(pszMac2,&mac),sizeof(mac));
	}
	if(pszMac3)
	{
		memcpy(&bootp.macAddr3,sz_to_mac(pszMac3,&mac),sizeof(mac));
	}
	
	printf("\nRewriting BOOTP block ...\n");
	if(!EmbedBootp(pszImageFile,&bootp))
	{
		printf("! ERROR: Modifying image!! Don't use it!!\n");
		return 1;
	}	

	printf("\nViewing modified BOOTP block ...\n");
	if(!ViewBootp(pszImageFile))
	{
		printf("! ERROR: Modified image is bad!! Don't use it!!\n");
		return 1;
	}
	printf("\nBOOTP changes done.\n");
	return 0;	
}


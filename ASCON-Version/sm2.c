#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdio.h>

/* sessKDF
 * input： cdata		-用于计算的数据串（二进制值）
 *		   datalen		-内容长度
 *		   keylen		-需要派生得到的长度
 * output：retdata		-计算后返回的内容（二进制值）,分配空间至少为需要keylen
 * return：0 as success, otherwise failed
*/
int sessKDF(unsigned char * cdata, int datalen, int keylen, char * retdata)
{
	int nRet = -1;
	unsigned char *pRet = NULL;
	unsigned char *pData = NULL;

	if (cdata == NULL || datalen <= 0 || keylen <= 0)
	{
		goto err;
	}

	if (NULL == (pRet = (unsigned char *)malloc(keylen)))
	{
		goto err;
	}

	if (NULL == (pData = (unsigned char *)malloc(datalen + 4)))
	{
		goto err;
	}

	memset(pRet, 0, keylen);
	memset(pData, 0, datalen + 4);

	unsigned char cdgst[32] = { 0 }; // 摘要
	unsigned char cCnt[4] = { 0 }; // 计数器的内存表示值
	int nCnt = 1;  // 计数器
	int nDgst = 32; // 摘要长度

	int nTimes = (keylen + 31) / 32; // 需要计算的次数
	int i = 0;
	memcpy(pData, cdata, datalen);
	for (i = 0; i < nTimes; i++)
	{
		// cCnt
		{
			cCnt[0] = (nCnt >> 24) & 0xFF;
			cCnt[1] = (nCnt >> 16) & 0xFF;
			cCnt[2] = (nCnt >> 8) & 0xFF;
			cCnt[3] = (nCnt) & 0xFF;
		}
		memcpy(pData + datalen, cCnt, 4);
		sm3(pData, datalen + 4, cdgst);

		if (i == nTimes - 1) // 最后一次计算，根据keylen/32是否整除，截取摘要的值
		{
			if (keylen % 32 != 0)
			{
				nDgst = keylen % 32;
			}
		}
		memcpy(pRet + 32 * i, cdgst, nDgst);

		i++;  // 
		nCnt++;  // 
	}

	if (retdata != NULL)
	{
		memcpy(retdata, pRet, keylen);
	}
	// printf("rdata: %x%x%x%x\n", retdata[0], retdata[1], retdata[2], retdata[3]);

	nRet = 0;
err:
	if (pRet)
		free(pRet);
	if (pData)
		free(pData);

	return nRet;
}
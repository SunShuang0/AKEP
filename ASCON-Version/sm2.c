#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdio.h>

/* sessKDF
 * input�� cdata		-���ڼ�������ݴ���������ֵ��
 *		   datalen		-���ݳ���
 *		   keylen		-��Ҫ�����õ��ĳ���
 * output��retdata		-����󷵻ص����ݣ�������ֵ��,����ռ�����Ϊ��Ҫkeylen
 * return��0 as success, otherwise failed
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

	unsigned char cdgst[32] = { 0 }; // ժҪ
	unsigned char cCnt[4] = { 0 }; // ���������ڴ��ʾֵ
	int nCnt = 1;  // ������
	int nDgst = 32; // ժҪ����

	int nTimes = (keylen + 31) / 32; // ��Ҫ����Ĵ���
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

		if (i == nTimes - 1) // ���һ�μ��㣬����keylen/32�Ƿ���������ȡժҪ��ֵ
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
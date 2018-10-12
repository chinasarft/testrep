#ifndef __TTOOL_AVREADER_H__
#define __TTOOL_AVREADER_H__

#include <stdint.h>

typedef enum {
	TTOOL_AUDIO_TYPE = 1,
	TTOOL_VIDEO_TYPE =2
}TToolAvType;

typedef enum {
	TTOOL_AUDIO_AAC= 1,
	TTOOL_AUDIO_G711 = 2,
	TTOOL_VIDEO_H264 = 3,
	TTOOL_VIDEO_H265 = 4
}TToolAvCodec;

typedef int (*TToolDataCallback)(void *opaque, void *pData, int nDataLen, TToolAvType avType, int64_t timestamp, int nIsKeyFrame);
typedef struct {
	int IsLoop;
	TToolAvCodec codec;
	const char *pFilePath;
	TToolDataCallback callback;
	void *pCbOpaque;
	int nG711FrameLen;
	int IsWithoutAdts;
}TToolReadArg;

int  TToolStartRead(TToolReadArg *pArg, void **pHandle);
int  TToolGetFrame(void *pHandle, const unsigned char **pFrame, int *nFrameLen, int *pIsKeyFrame);
void TToolStopRead(void **pHandle);

#endif

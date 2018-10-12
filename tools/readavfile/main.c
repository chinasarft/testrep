#include "avreader.h"
#include "flag.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct {
	bool IsWithoutAdts;
	bool IsTestH264;
	bool IsTestH265;
	bool IsTestAAC;
	bool IsTestG711;
	const char *pAFilePath;
	const char *pVFilePath;
}CmdArg;
CmdArg cmdArg;

static void printRes(int nIsKey, const unsigned char *d, int dLen) {
	printf("I:%d L:%d |", nIsKey, dLen);
	if (dLen <= 0) {
		printf("dlen abnormal:%d\n", dLen);
		return;
	}
	if (dLen > 62) {
		dLen = 62;
	}
	for(int i = 0; i < dLen; i++) {
		printf("%02x ", d[i]);
	}
	printf("\n");
}

void testH264() {
	TToolReadArg arg;
	memset(&arg, 0, sizeof(arg));
	arg.IsLoop = 0;
	arg.codec = TTOOL_VIDEO_H264;
	if (cmdArg.pAFilePath)
		arg.pFilePath = cmdArg.pVFilePath;
	else 
		arg.pFilePath = "/Users/liuye/qbox/linking/link/libtsuploader/pcdemo/material/h265_aac_1_16000_h264.h264";
	arg.callback = NULL;
	arg.pCbOpaque = NULL;
	arg.nG711FrameLen = 160;
	arg.IsWithoutAdts = 1;

	void *pHandle;
	int ret = TToolStartRead(&arg, &pHandle);
	if (ret != 0) {
		fprintf(stderr, "TToolStartRead fail:%d\n", ret);
		exit(1);
	}

	const unsigned char *pFrame;
	int nFrameLen;
	int nIsKeyFrame;
	while(1) {
		ret = TToolGetFrame(pHandle, &pFrame, &nFrameLen, &nIsKeyFrame);
		if (ret != 0) {
			break;
		}
		printRes(nIsKeyFrame, pFrame, nFrameLen);
	}

}

void testAAC() {
	TToolReadArg arg;
	memset(&arg, 0, sizeof(arg));
	arg.IsLoop = 0;
	arg.codec = TTOOL_AUDIO_AAC;
	if (cmdArg.pAFilePath)
		arg.pFilePath = cmdArg.pAFilePath;
	else 
		arg.pFilePath = "/Users/liuye/qbox/linking/link/libtsuploader/pcdemo/material/h265_aac_1_16000_a.aac";
	arg.callback = NULL;
	arg.pCbOpaque = NULL;
	arg.nG711FrameLen = 160;
	arg.IsWithoutAdts = cmdArg.IsWithoutAdts;

	void *pHandle;
	int ret = TToolStartRead(&arg, &pHandle);
	if (ret != 0) {
		fprintf(stderr, "TToolStartRead fail:%d\n", ret);
		exit(1);
	}

	const unsigned char *pFrame;
	int nFrameLen;
	int nIsKeyFrame;
	while(1) {
		ret = TToolGetFrame(pHandle, &pFrame, &nFrameLen, &nIsKeyFrame);
		if (ret != 0) {
			break;
		}
		printRes(0, pFrame, nFrameLen);
	}
}

void testG711() {
	TToolReadArg arg;
	memset(&arg, 0, sizeof(arg));
	arg.IsLoop = 0;
	arg.codec = TTOOL_AUDIO_G711;
	if (cmdArg.pAFilePath)
		arg.pFilePath = cmdArg.pAFilePath;
	else 
		arg.pFilePath = "/Users/liuye/qbox/linking/link/libtsuploader/pcdemo/material/h265_aac_1_16000_pcmu_8000.mulaw";
	arg.callback = NULL;
	arg.pCbOpaque = NULL;
	arg.nG711FrameLen = 320;

	void *pHandle;
	int ret = TToolStartRead(&arg, &pHandle);
	if (ret != 0) {
		fprintf(stderr, "TToolStartRead fail:%d\n", ret);
		exit(1);
	}

	const unsigned char *pFrame;
	int nFrameLen;
	int nIsKeyFrame;
	while(1) {
		ret = TToolGetFrame(pHandle, &pFrame, &nFrameLen, &nIsKeyFrame);
		if (ret != 0) {
			break;
		}
		printRes(0, pFrame, nFrameLen);
	}
}

#define VERSION "v1.0.0"
int main(int argc, const char **argv){

	flag_bool(&cmdArg.IsWithoutAdts, "noadts", "get aac frame with no adts header");
        flag_bool(&cmdArg.IsTestH264, "testh264", "input is h264 file");
        flag_bool(&cmdArg.IsTestH265, "testh265", "input is h265 file");
        flag_bool(&cmdArg.IsTestAAC, "testaac", "input is aac file");
        flag_bool(&cmdArg.IsTestG711, "testg711", "input is g711 file");
	flag_str(&cmdArg.pAFilePath, "afile", "set input audio file path.like /root/a.aac");
	flag_str(&cmdArg.pVFilePath, "vfile", "set input video file path.like /root/a.h264");

        if (argc == 1 || (argc >=2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-help") == 0))) {
                flag_write_usage(argv[0]);
                return 0;
        }
	flag_parse(argc, argv, VERSION);

	if (cmdArg.IsTestH264) {
		testH264();
	}
	if (cmdArg.IsTestAAC) {
		testAAC();
	}
	if (cmdArg.IsTestG711) {
		testG711();
	}
}

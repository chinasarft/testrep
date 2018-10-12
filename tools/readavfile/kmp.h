#ifndef __TTOOL_KMP_H__
#define __TTOOL_KMP_H__

typedef struct {
	const unsigned char * pattern;
	int patternSize;
	int prefix[32];
	int prefixLen;
}KMP;

int InitKmp(KMP *pKmp, const unsigned char *pattern, int patternSize);
int FindPatternIndex(KMP *pKmp, const unsigned char*s, int sLen);

#endif

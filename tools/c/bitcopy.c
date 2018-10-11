#include <stdio.h>
#include <string.h>
void bitcopy(void *dst, int nDstOffsetBit, const void *src, int nSrcOffsetBit, int nCopyBitLen)
{
	unsigned char * d = (unsigned char *)dst + nDstOffsetBit / 8;
	unsigned char * s = (unsigned char *)src + nSrcOffsetBit / 8;

	int len = nCopyBitLen / 8;
	int remainBit = nCopyBitLen % 8;
	if (nDstOffsetBit == 0 && nSrcOffsetBit == 0) {
		if (len > 0) {
			memcpy(dst, src, len);
		}
		if (remainBit > 0) {
			d[len] = ( (s[len] & (0xff << (8-remainBit))) | (d[len] & (0xff >> remainBit)) );
		}
		return;
	}

	if (nDstOffsetBit == 0 && nSrcOffsetBit != 0) {
		for (int i = 0; i < len; i++) {
			d[i] = ((s[i] & (0xff >> nSrcOffsetBit)) << nSrcOffsetBit) |
			       ((s[i+1] & (0xff << (8 - nSrcOffsetBit))) >> (8 - nSrcOffsetBit));
		}
		if (remainBit > 0) {
			int remainAddOffsetLen = remainBit + nSrcOffsetBit;
			if (remainAddOffsetLen <= 8) {
				d[len] = ( ((s[len] & (0xff << (8-remainAddOffsetLen))) << nSrcOffsetBit) | (d[len] & (0xff >> remainBit)) );
			} else {
				//d[len] = ( ((s[len] << nSrcOffsetBit) & (0xff << nSrcOffsetBit)) |
				d[len] = ( (s[len] << nSrcOffsetBit) |
						((s[len+1] & (0xff << (8-(remainAddOffsetLen - 8)))) >> (8 - nSrcOffsetBit)) |
					       	(d[len] & (0xff >> remainBit)) );
			}
		}
		return;
	}

	if (nDstOffsetBit != 0 && nSrcOffsetBit == 0) {
		for (int i = 0; i < len; i++) {
			d[i] = ((s[i] & (0xff << nDstOffsetBit)) >> nDstOffsetBit) | (d[i] & (0xff << (8 - nDstOffsetBit)));
			d[i+1] = ((s[i] & (0xff >> (8 - nDstOffsetBit))) << (8 - nDstOffsetBit)) | (d[i+1] & (0xff >> nDstOffsetBit));
		}
		if (remainBit > 0) {
			int remainAddOffsetLen = remainBit + nDstOffsetBit;
			if (remainAddOffsetLen <= 8) {
				d[len] = (d[len] & (0xff << (8 - nDstOffsetBit))) | //save most nDstOffsetBit bits
				       	((s[len] & (0xff << (8 - remainBit))) >> nDstOffsetBit) |
				       	(d[len] & (0xff >> remainAddOffsetLen)); //save least (8 - remainAddOffsetLen) bits
			} else {
				d[len] = (d[len] & (0xff << (8 - nDstOffsetBit))) |
				       	((s[len] & (0xff << nDstOffsetBit)) >> nDstOffsetBit);

				int bitPos = 8 - nDstOffsetBit;
				d[len+1] = ((s[len] & (0xff << (8 - remainBit))) << bitPos) |
					(d[len+1] & (0xff >> (remainAddOffsetLen - 8)));

			}
		}
		return;
	}
	if (nDstOffsetBit != 0 && nSrcOffsetBit != 0) {
		return;
	}
}

void printHex(void *data, int s) {
	unsigned char * d = (unsigned char *)data;
	for (int i = 0; i < s; i++) {
		printf("%02x ", d[i]);
	}
	printf("\n");
}

void test_offset_zero() {
	unsigned char dst[10];
	unsigned char src[10] = {0b00000000, 0b00000000, 0x00000000};

	//copy bit小于等于8位
	for(int i = 0; i <= 8; i++) {
		dst[0] = 0xff;
		bitcopy(dst, 0, src, 0, i);
		if (dst[0] != (0xff >> i)) {
			fprintf(stderr, "test_offset_zero 1 i=%d error:%d %d\n",i, dst[i], (0xff >> i));
		}
	}

	//copy bit数n    8 < n <=16
	for(int i = 0; i <= 8; i++) {
		dst[0] = 0xff;
		dst[1] = 0xff;
		bitcopy(dst, 0, src, 0, i+8);
		if (dst[0] != 0 && dst[1] != (0xff >> i)) {
			fprintf(stderr, "test_offset_zero 2 i=%d error:%d %d\n",i, dst[i], (0xff >> i));
		}
	}

	//copy bit数n    16 < n <=24
	for(int i = 0; i <= 8; i++) {
		dst[0] = 0xff;
		dst[1] = 0xff;
		dst[2] = 0xff;
		bitcopy(dst, 0, src, 0, i+16);
		if (dst[0] != 0 && dst[1] != 0 && dst[2] != (0xff >> i)) {
			fprintf(stderr, "test_offset_zero 3 i=%d error:%d %d\n",i, dst[i], (0xff >> i));
		}
	}

}

void test_dst_offset_zero() {
	unsigned char dst[10];
	unsigned char src[10] = {0b10101010, 0b10101010};

	//copy bit小于等于8位, 并且src偏移1位
	unsigned char res[9] = {0b11111111, 0b01111111, 0b01111111, 0b01011111, 0b01011111, 0b01010111, 0b01010111, 0b01010101, 0b01010101};
	for(int i = 0; i <= 8; i++) {
		dst[0] = 0xff;
		bitcopy(dst, 0, src, 1, i);
		if (dst[0] != res[i]) {
			fprintf(stderr, "test_dst_offset_zero 1 i=%d error:%d %d\n", i, dst[i], (0xff >> i));
		}
	}

	//copy bit小于等于8位, 并且src偏移2位
	unsigned res2[9] = {0b11111111, 0b11111111, 0b10111111, 0b10111111, 0b10101111, 0b10101111, 0b10101011, 0b10101011, 0b10101010};
	for(int i = 0; i <= 8; i++) {
		dst[0] = 0xff;
		bitcopy(dst, 0, src, 2, i);
		if (dst[0] != res2[i]) {
			fprintf(stderr, "test_dst_offset_zero 2 i=%d error:%d %d\n", i, dst[i], (0xff >> i));
		}
	}

}

void test_src_offset_zero() {
}

int main() {
	test_offset_zero();
	test_dst_offset_zero();
	char dst[10];
	char src[10] = {0b11110000, 0b10001000, 0b01010101};

	memset(dst, 0xff, sizeof(dst));
	bitcopy(dst, 0, src, 0, 10);
	printHex(dst, 2);
	
	// 11000010 00111111
	memset(dst, 0xff, sizeof(dst));
	bitcopy(dst, 0, src, 2, 11);
	printHex(dst, 2);

	// 11000010 00101001
	memset(dst, 0xff, sizeof(dst));
	bitcopy(dst, 0, src, 2, 15);
	printHex(dst, 2);

	// 11111100 00100111
	memset(dst, 0xff, sizeof(dst));
	bitcopy(dst, 2, src, 0, 11);
	printHex(dst, 2);

	//11111100 00100010 01111111
	memset(dst, 0xff, sizeof(dst));
	bitcopy(dst, 2, src, 0, 15);
	printHex(dst, 3);
}

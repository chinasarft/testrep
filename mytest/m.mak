a:
	g++ -g testRTSPClient.cpp -I../UsageEnvironment/include -I../groupsock/include -I../liveMedia/include -I../BasicUsageEnvironment/include -I. -DSOCKLEN_T=int -DLOCALE_NOT_USED -D__MINGW32__ -Wall -Wno-deprecated ../liveMedia/libliveMedia.a ../groupsock/libgroupsock.a ../BasicUsageEnvironment/libBasicUsageEnvironment.a ../UsageEnvironment/libUsageEnvironment.a -lws2_32 -o test


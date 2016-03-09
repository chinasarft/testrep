
a:
	g++ -g testRTSPClient.cpp -I../live555/UsageEnvironment/include -I../live555/groupsock/include -I../live555/liveMedia/include -I../live555/BasicUsageEnvironment/include -I. -DSOCKLEN_T=int -DLOCALE_NOT_USED -D__MINGW32__ -Wall -Wno-deprecated ../live555/liveMedia/libliveMedia.a ../live555/groupsock/libgroupsock.a ../live555/BasicUsageEnvironment/libBasicUsageEnvironment.a ../live555/UsageEnvironment/libUsageEnvironment.a -lws2_32 -o test


CXX=g++
CXXFLAGS = -g -DWIN32 -I../rtmpdump/ -I../live555/UsageEnvironment/include -I../live555/groupsock/include -I../live555/liveMedia/include -I../live555/BasicUsageEnvironment/include -I. -DSOCKLEN_T=int -DLOCALE_NOT_USED -D__MINGW32__
#-Wall -Wno-deprecated
LDFLAGS = -L. -L../live555/liveMedia  -L../live555/groupsock/ -L../live555/BasicUsageEnvironment -L../live555/UsageEnvironment -L../rtmpdump/librtmp
LIBS = -lliveMedia -lgroupsock -lBasicUsageEnvironment -lUsageEnvironment -lrtmp -lws2_32 -lssl -lcrypto -lwinmm -lz

a:rtsp2rtmp.o
	$(CXX) $^ -o tran $(LDFLAGS) $(LIBS)
#	g++ -g rtsp2rtmp.cpp -I../live555/UsageEnvironment/include -I../live555/groupsock/include -I../live555/liveMedia/include -I../live555/BasicUsageEnvironment/include -I. -DSOCKLEN_T=int -DLOCALE_NOT_USED -D__MINGW32__ -Wall -Wno-deprecated ../live555/liveMedia/libliveMedia.a ../live555/groupsock/libgroupsock.a ../live555/BasicUsageEnvironment/libBasicUsageEnvironment.a ../live555/UsageEnvironment/libUsageEnvironment.a -lws2_32 -o test

rtmpr: simplest_librtmp_receive/simplest_librtmp_receive.o
	$(CXX) $^  -o recv $(LDFLAGS) $(LIBS)
rtmpf:simplest_librtmp_send_flv/simplest_librtmp_sendflv.o
	$(CXX) $^ -o sendflv  $(LDFLAGS) $(LIBS)

rtmp2:simplest_librtmp_send264/simplest_librtmp_send264.o simplest_librtmp_send264/librtmp_send264.o
	$(CXX) $^ -o send264 $(LDFLAGS) $(LIBS)



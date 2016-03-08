CXX=g++
LD=ld
LDFLAGS = -L. 
CXXFLAGS = -g -I../../rtmpdump/
LIBS = -lrtmp -lws2_32 -lssl -lcrypto -lwinmm -lz

r: simplest_librtmp_receive/simplest_librtmp_receive.o
	$(CXX) $^  -o recv $(LDFLAGS) $(LIBS)
f:simplest_librtmp_send_flv/simplest_librtmp_sendflv.o
	$(CXX) $^ -o sendflv  $(LDFLAGS) $(LIBS)

t:simplest_librtmp_send264/simplest_librtmp_send264.o simplest_librtmp_send264/librtmp_send264.o
	$(CXX) $^ -o send264 $(LDFLAGS) $(LIBS)

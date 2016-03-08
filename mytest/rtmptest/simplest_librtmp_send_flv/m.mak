a:
	g++ simplest_librtmp_sendflv.cpp -I../../../rtmpdump -L../ -lrtmp -lws2_32 -lssl -lcrypto -lwinmm -lz -o flv 

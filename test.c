#include "netspeed.h"

void printspeed(struct NetSpeedSet *n){
    int i;
    for(i = 0; i < n->len; i++){
        printf("%5d:%5d %5d ",n->ns[i].pid, n->ns[i].up, n->ns[i].down);
        if(i > 0 && i % 15 == 0)
            printf("\n");
    }
	printf("\n");
}

int test1(int argc, char **argv){
	struct NetSpeedSet * ns;
    if(argc < 3){
        printf("usage as:%s ifname pid1 pid2 ...\n", argv[0]);
        exit (4);
    }
    ns = queryPidNetStream( argv[2], argv[1]);
	if(ns == NULL){
	    printf("queryPidNetStream fail");
		return -1;
	}
	printspeed(ns);
}

int test2(int argc, char **argv){
    int times;
	struct NetSpeedSet *ns;
	char str[1000]={0};
    if(argc < 4){
        printf("usage as:%s ifname times pid1 pid2 ...\n", argv[0]);
        exit (5);
    }
    times = atoi(argv[2]);
	printf("times=%d argv[3]=%s\n",times, argv[3]);
    while(times--){
	strcpy(str, argv[3]);
	if(str[strlen(str)-1] != ',')
		str[strlen(str)] = ',';
        ns = queryPidNetStream( str, argv[1]);
		memset(str, 0, sizeof(str));
		if(ns == NULL){
		    printf("queryPidNetStream fail");
			continue;
		}
        printspeed(ns);
    }
}
int main(int argc, char **argv){
        //test1(argc, argv);
        test2(argc, argv);

}

# Makefile for ddos_attack
# author:cp
# time:2008-4-11

CC = gcc
all:ddosClient
.PHONY:all

LIBS = -L /usr/lib64 -I /usr/include/libxml2/ 
OBJECTS = ddosClient.o attack.o  xmlctr.o   package.o  dataList.o  packetTime.o sendResultFile.o getconfigfromtext.o

ddosClient: $(OBJECTS)
	      $(CC) -o $@ $(OBJECTS) $(LIBS) -lxml2 -l pthread

ddosSend: $(OBJECTS2)
	      $(CC) -o $@ $(OBJECTS2) $(LIBS) -lxml2 -l pthread
	
ddosClient.o:ddosClient.c
		$(CC) -Wall -c ddosClient.c
ddosClientSingal.o:ddosClientSingal.c
		$(CC) -Wall -c ddosClientSingal.c
attack.o:attack.c
		$(CC) -Wall -c attack.c $(LIBS)
xmlctr.o:xmlctr.c
		$(CC) -Wall -c xmlctr.c $(LIBS)
package.o:package.c
		$(CC) -Wall -c package.c $(LIBS)
dataList.o:dataList.c
		$(CC) -Wall -c dataList.c $(LIBS) 
packetTime.o:packetTime.c
		$(CC) -Wall -c packetTime.c $(LIBS)
sendResultFile.o:sendResultFile.c
		$(CC) -Wall -c sendResultFile.c
getconfigfromtext.o:getconfigfromtext.c
		$(CC) -Wall -c getconfigfromtext.c

clean:
	rm *.o




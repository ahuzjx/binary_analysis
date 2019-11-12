CC = g++ 
CFLAGS = -g -std=c++11 
OBJS = elf_parser.o \
       main.o 
INCLUDES =-I. -I./include
LIBS= -L.
PUBFLAGS = -ludis86
TARGET = elf_parser
all:$(TARGET)
 
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(INCLUDES) $(LIBS) $(PUBFLAGS)  
.SUFFIXES:.o .h
.SUFFIXES:.cpp .o
.cpp.o:
	$(CC) -c $(CFLAGS) -o $@ $< $(INCLUDES) 
clean:
	rm -rf $(TARGET) $(OBJS) core *.log

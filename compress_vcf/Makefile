CC		=	gcc

CFLAGS	=	-O3 -Wall

C_SOURCES 	=	compress_vcf.c

C_OBJECTS	=	$(C_SOURCES:.c=.o)

EXECUTABLE	=	compress_vcf

all: $(SOURCES) $(EXECUTABLE)
	rm -fr $(C_OBJECTS)

$(EXECUTABLE): $(C_OBJECTS)
	$(CC) $(C_OBJECTS) -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@
clean:
	rm -f $(EXECUTABLE) *.o *~

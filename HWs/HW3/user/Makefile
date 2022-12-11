TARGET=main # target compiler output flie name

all: main.o utils.o validation.o
	gcc main_file_object.o utils.o validation.o -lm -o $(TARGET)

main_file_object.o: main.h
	gcc main.c -lm -o main.o

utils.o: utils.h
	gcc utils.c -lm -o utils.o

validation.o: validation.h
	gcc validation.c -lm -o validation.o

clean:
	rm $(TARGET)

virus_detector: virus_detector.o
	gcc -g -m32 -Wall -o virus_detector virus_detector.o
virus_detector.o: virus_detector.c
	gcc -g -m32 -Wall -c virus_detector.c -o virus_detector.o

.PHONY: clean
clean:
	rm -f virus_detector.o virus_detector
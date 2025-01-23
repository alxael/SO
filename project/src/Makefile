COMPILER = gcc
FILESYSTEM_FILES = main.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o pseudofs `pkg-config fuse3 --cflags --libs`
	echo 'To Mount: ./pseudofs -f [mount point]'

clean:
	rm pseudofs
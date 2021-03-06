CC=gcc

ifeq ($(shell uname), Linux)
	USBFLAGS = `libusb-config --cflags`
	USBLIBS = `libusb-config --libs`
	EXE_SUFFIX =
	OSFLAG = -D LINUX
else ifeq ($(shell uname), Darwin)
	USBFLAGS = `libusb-config --cflags`
	USBLIBS = `libusb-config --libs`
	EXE_SUFFIX =
	OSFLAG = -D LINUX
else
	USBFLAGS = -I \include
	USBLIBS = -L \lib -lusb
	EXE_SUFFIX = .exe
	OSFLAG = -D WIN
endif

LIBS    = $(USBLIBS)  -fPIC -shared -lcrypto -ldl
INCLUDE = library
CFLAGS  = $(USBFLAGS) $(LIBS) -I$(INCLUDE) -O -g $(OSFLAG)

LWLIBS = littleWire littleWire_util littleWire_servo opendevice spi mfrc522
SRCS = pam_usbkey

OFILE=pam_usbkey.so
SECDIR=/lib/x86_64-linux-gnu/security/

.PHONY:	clean library docs

all: library $(SRCS)

library: $(LWLIBS)

$(LWLIBS):
	@echo Building library: $@...
	$(CC) $(CFLAGS) -c library/$@.c 

$(SRCS): $(addsuffix .o, $(LWLIBS))
	@echo Building execurable: $@...
	$(CC) $(CFLAGS) -o $@$(EXE_SUFFIX).so src/$@.c $^ $(LIBS)

docs:
	doxygen ./docs/doxygen.conf
	cd ./docs/latex/; make all

clean:
	rm -rf $(SRCS)$(EXE_SUFFIX) *.o *.exe *.dSYM docs/html docs/latex

install:
	cp $(OFILE) $(SECDIR)
	@if [ -f $(SECDIR)$(OFILE) ]; then \
		echo "\n> Successfully installed, now modify pam file accordingly\n"; \
	else \
		echo "> Unable to install. Did you run as root?"; \
	fi


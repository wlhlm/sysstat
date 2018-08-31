# sysstat - simple i3 status bar
# See LICENSE file for copyright and license details.

# sysstat version
VERSION = 0.2

# Programm name
NAME = sysstat

# Includes and libs
LIBS = libmpdclient yajl
INCS = `pkg-config --cflags --libs ${LIBS}`

# Flags
CPPFLAGS = -DVERSION=\"${VERSION}\" -DNAME=\"${NAME}\" -D_POSIX_C_SOURCE=200809L
CFLAGS = -std=c99 -pedantic -Wall -Os ${INCS} ${CPPFLAGS} -lm

# Enable debugging symbols
ifdef DEBUG
	CFLAGS += -g
endif

# Compiler and linker
CC ?= cc

# Source files
SRC = sysstat.c fuzzyclock.c

all: options ${NAME}

options:
	@echo ${NAME} build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "CC       = ${CC}"

$(NAME): ${SRC}
	@${CC} -o ${NAME} ${SRC} ${CFLAGS}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f ${NAME} ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/${NAME}

clean:
	@echo Cleaning
	@rm -f ${NAME}

.PHONY: all options install clean

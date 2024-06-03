# sysstat - simple i3 status bar
# See LICENSE file for copyright and license details.
.POSIX:

# sysstat version
VERSION = 0.3

# Programm name
NAME = sysstat

# Includes and libs
LIBS = libmpdclient yajl
INCS = `pkg-config --cflags ${LIBS}`
LDINCS = `pkg-config --libs ${LIBS}`

# Flags
CPPFLAGS = -DVERSION=\"${VERSION}\" -DNAME=\"${NAME}\" -D_POSIX_C_SOURCE=200809L
LDFLAGS := -lm ${LDFLAGS} ${LDINCS}
CFLAGS := -std=c99 -pedantic -Wall -Os ${CFLAGS} ${INCS} ${CPPFLAGS} ${LDFLAGS}

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

$(NAME): ${SRC} config.h
	@${CC} -o ${NAME} ${SRC} ${CFLAGS}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p "${DESTDIR}${PREFIX}/bin"
	@cp -f ${NAME} "${DESTDIR}${PREFIX}/bin"
	@chmod 755 "${DESTDIR}${PREFIX}/bin/${NAME}"

uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f "${DESTDIR}${PREFIX}/bin/${NAME}"

clean:
	@echo Cleaning up
	@rm -f ${NAME}

.PHONY: all options install clean

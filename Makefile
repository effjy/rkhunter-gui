# Makefile for rkhunter-gui — a GTK3 front-end for rkhunter (Rootkit Hunter)
#
#   make            build the program
#   make run        build and run
#   sudo make install     (also installs bundled rkhunter if it is missing)
#   sudo make uninstall   (removes the GUI; leaves rkhunter in place)

PROG    := rkhunter-gui
SRC     := rkhunter-gui.c
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += $(shell pkg-config --cflags gtk+-3.0)
LIBS    := $(shell pkg-config --libs gtk+-3.0)

PREFIX  ?= /usr/local
BINDIR  := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share
APPDIR  := $(DATADIR)/applications
ICONDIR := $(DATADIR)/icons/hicolor/scalable/apps

# Bundled rkhunter source — used by "make install" when rkhunter is missing.
RKH_VER  := 1.4.6
RKH_TAR  := rkhunter-$(RKH_VER).tar.gz

.PHONY: all run clean install uninstall install-rkhunter

all: $(PROG)

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

run: $(PROG)
	./$(PROG)

clean:
	rm -f $(PROG)

# Install the bundled rkhunter only if it is not already on the system.
install-rkhunter:
	@if command -v rkhunter >/dev/null 2>&1; then \
	    echo "rkhunter already installed at $$(command -v rkhunter) — skipping."; \
	elif [ "$$(id -u)" != "0" ]; then \
	    echo "rkhunter not found and not running as root; run 'sudo make install'."; \
	    exit 1; \
	else \
	    echo "rkhunter not found — installing bundled $(RKH_TAR) …"; \
	    tmp=$$(mktemp -d) && \
	    tar -xzf $(RKH_TAR) -C $$tmp && \
	    ( cd $$tmp/rkhunter-$(RKH_VER) && sh installer.sh --layout default --install ) && \
	    rm -rf $$tmp && \
	    rkhunter --propupd --nocolor >/dev/null 2>&1 || true; \
	    echo "rkhunter installed."; \
	fi

install: install-rkhunter $(PROG)
	install -d $(BINDIR)
	install -m 0755 $(PROG) $(BINDIR)/$(PROG)
	install -d $(ICONDIR)
	install -m 0644 $(PROG).svg $(ICONDIR)/$(PROG).svg
	install -d $(APPDIR)
	install -m 0644 $(PROG).desktop $(APPDIR)/$(PROG).desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo "Installed $(PROG) to $(BINDIR)"

uninstall:
	rm -f $(BINDIR)/$(PROG)
	rm -f $(ICONDIR)/$(PROG).svg
	rm -f $(APPDIR)/$(PROG).desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo "Uninstalled $(PROG)"

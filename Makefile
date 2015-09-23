it: all

PACKAGE := pam_rundir
VERSION := 1.0.0
POD2MAN := pod2man

include config.mak

BINS = $(PACKAGE).so
OBJS = $(PACKAGE).o
DOCS = $(PACKAGE).8

$(BINS): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) -lpam

%.o: %.c
	$(CC) -fPIC -c $^

%.8: %.pod
	$(POD2MAN) --center="$(PACKAGE)" --section=8 --release="$(VERSION)" $(basename $@).pod > $@

all: $(BINS) $(DOCS)

tgz: distclean $(DOCS)
	rm -rf /tmp/$(PACKAGE)-$(VERSION) && \
	cp -a . /tmp/$(PACKAGE)-$(VERSION) && \
	cd /tmp && \
	tar -zpcv --owner=0 --group=0 --numeric-owner --exclude=.git* -f /tmp/$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION) && \
	exec rm -rf /tmp/$(PACKAGE)-$(VERSION)

install: it
	for bin in $(BINS); do \
		install -Dm755 $$bin $(DESTDIR)$(securedir)/$$bin; \
	done
	for f in $(DOCS); do \
		install -Dm644 $$f $(DESTDIR)/usr/share/man/man8/$$f; \
	done

clean:
	rm -f $(BINS) $(OBJS)
distclean: clean
	rm -f $(DOCS)
	rm -f config.mak config.h

.PHONY: install it all clean distclean

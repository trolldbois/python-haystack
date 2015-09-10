#!/usr/bin/make -f
COMMIT=$(shell git rev-parse HEAD)

# make tgz for distribution
srctgz:
	tar zcf src-$(COMMIT).tgz src/ --exclude=*.py --exclude=*.pyc --exclude=*.tgz



#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2018 Joyent, Inc.
# Copyright 2022 MNX Cloud, Inc.
#

# The prebuilt sdcnode version we want. See
# "tools/mk/Makefile.node_prebuilt.targ" for details.
NODE_PREBUILT_VERSION=v6.17.1
ifeq ($(shell uname -s),SunOS)
        NODE_PREBUILT_TAG=zone64
        # minimal-64-lts@21.4.0
        NODE_PREBUILT_IMAGE=a7199134-7e94-11ec-be67-db6f482136c2
endif

NAME = ufds-notifier

#
# Tools
#
# Get md2man-roff from <https://github.com/sunaku/md2man>
MD2MAN		:= md2man-roff
TAP		:= ./node_modules/.bin/tape

#
# Files
#
JS_FILES	:= $(shell find lib -name '*.js')
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE	 = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS	 = -f tools/jsstyle.conf

# MAN_PAGES       := $(shell ls man/src)
# MAN_OUTDIR      := man/man1
# MAN_OUTPAGES=$(MAN_PAGES:%.md=$(MAN_OUTDIR)/%.1)
# MAN_ROOT        := man/src

ENGBLD_USE_BUILDIMAGE	= true
ENGBLD_REQUIRE          := $(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
TOP ?= $(error Unable to access eng.git submodule makefiles.)

BUILD_PLATFORM  = 20210826T002459Z

ifeq ($(shell uname -s),SunOS)
        include ./deps/eng/tools/mk/Makefile.node_prebuilt.defs
        include ./deps/eng/tools/mk/Makefile.agent_prebuilt.defs
else
        NPM=npm
        NODE=node
        NPM_EXEC=$(shell which npm)
        NODE_EXEC=$(shell which node)
endif
include ./deps/eng/tools/mk/Makefile.smf.defs

# include ./tools/mk/Makefile.defs
# include ./tools/mk/Makefile.node_deps.defs

ROOT            := $(shell pwd)
RELEASE_TARBALL := $(NAME)-pkg-$(STAMP).tar.gz
RELSTAGEDIR          := /tmp/$(NAME)-$(STAMP)

#
# Repo-specific targets
#
.PHONY: all
all: $(NPM_EXEC) $(REPO_DEPS)
	$(NPM) install --production

CLEAN_FILES += $(TAP) ./node_modules/tap

# triton-origin-x86_64-21.4.0
BASE_IMAGE_UUID = 502eeef2-8267-489f-b19c-a206906f57ef
BUILDIMAGE_NAME = $(NAME)
BUILDIMAGE_DESC = UFDS-NOTIFIER

.PHONY: test
test: all
	TAP=1 $(TAP) test/*.js

.PHONY: coverage
coverage: all
	$(NPM_EXEC) install istanbul && \
	    ./node_modules/.bin/istanbul cover \
	    $(TAP) test/*.js

.PHONY: codecovio
codecovio: coverage
	$(NPM_EXEC) install codecov.io && \
	    ./node_modules/.bin/codecov < coverage/lcov.info

$(MAN_OUTDIR):
	mkdir -p $@

$(MAN_OUTDIR)/%.1: $(MAN_ROOT)/%.md | $(MAN_OUTDIR)
	$(MD2MAN) $^ > $@

.PHONY: manpages
manpages: $(MAN_OUTPAGES)

#
# Packaging targets
#

.PHONY: release
release: all deps docs $(SMF_MANIFESTS)
	@echo "Building $(RELEASE_TARBALL)"
	@mkdir -p $(RELSTAGEDIR)/root/opt/smartdc/ufds-notifier/build
	@mkdir -p $(RELSTAGEDIR)/site
	@touch $(RELSTAGEDIR)/site/.do-not-delete-me
	cp -PR $(NODE_INSTALL) $(RELSTAGEDIR)/root/opt/smartdc/ufds-notifier/build/node
	cp -r   $(ROOT)/bin \
		$(ROOT)/etc \
		$(ROOT)/lib \
		$(ROOT)/node_modules \
		$(ROOT)/package.json \
		$(ROOT)/smf/manifests/ufds-notifier.xml \
		$(ROOT)/server.js \
		$(ROOT)/tools \
		$(ROOT)/tpl \
		$(RELSTAGEDIR)/root/opt/smartdc/ufds-notifier/
	(cd $(RELSTAGEDIR) && $(TAR) -I pigz -cf $(ROOT)/$(RELEASE_TARBALL) root site)
	@rm -rf $(RELSTAGEDIR)


.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/ufds-notifier
	cp $(ROOT)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/ufds-notifier/$(RELEASE_TARBALL)

.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/$(NAME)
	cp $(TOP)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)

include ./deps/eng/tools/mk/Makefile.deps
ifeq ($(shell uname -s),SunOS)
        include ./deps/eng/tools/mk/Makefile.node_prebuilt.targ
        include ./deps/eng/tools/mk/Makefile.agent_prebuilt.targ
endif
include ./deps/eng/tools/mk/Makefile.smf.targ
include ./deps/eng/tools/mk/Makefile.targ

# include ./tools/mk/Makefile.deps
# include ./tools/mk/Makefile.node_deps.targ
# include ./tools/mk/Makefile.targ

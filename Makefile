###########################################################################
# Copyright 2017 ZT Prentner IT GmbH (www.ztp.at)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
###########################################################################

LANGS			= de
TURNOVER_COUNTER_SIZES	= 5,8,16
TEST_FILES		= $(shell find tests/ -name '*.json' | sort)

setup: aesBase64_1.txt cert_1.key cert_1.crt cert_1.pub

test: cert_1.key cert_1.crt cert_1.pub
	python2.7 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 2' $(TEST_FILES)
	if command -v python3 >/dev/null 2>&1 && [ -z "$${VIRTUAL_ENV}" ] ; then \
		python3 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 3' $(TEST_FILES) ; \
	fi

aesBase64_%.txt:
	dd if=/dev/urandom bs=1 count=32 | base64 > $@

cert_%.pub: cert_%.crt
	openssl x509 -noout -pubkey -in $< > $@

cert_%.crt: cert_%.key
	openssl req -new -x509 -key $< -out $@

cert_%.key:
	openssl ecparam -name prime256v1 -genkey -out $@

update-trans: $(addprefix lang/,$(addsuffix /LC_MESSAGES/rktool.po, $(LANGS)))

compile-trans: $(addprefix lang/,$(addsuffix /LC_MESSAGES/rktool.mo, $(LANGS)))

lang/%/LC_MESSAGES/rktool.mo: lang/%/LC_MESSAGES/rktool.po
	msgfmt -o $@ $<

lang/%/LC_MESSAGES/rktool.po: lang/rktool.pot
	mkdir -p $(dir $@)
	if [ -f $@ ]; then \
		msgmerge -o $@ $@ $< ; \
	else \
		msginit -o $@ --locale=$* --input $< ; \
	fi

lang/rktool.pot:
	mkdir -p lang
	pygettext.py -o lang/rktool.pot librksv/*.py librksv/test/*.py *.py *.kv

env: .pyenv
	echo "Virtualenv ready. Run \"source .pyenv/bin/activate\" to enable it."

NO_VENV_PATH=$(shell echo $${PATH} | sed -e 's;$(CURDIR)/.pyenv/bin:;;')
DISABLE_VENV=unset pydoc; \
    export PATH=$(NO_VENV_PATH); \
    unset PYTHONHOME; \
    unset VIRTUAL_ENV

ifneq (,$(findstring n,$(MAKEFLAGS)))
DISABLE_VENV=: DISABLE_VENV
endif

.pyenv: misc/requirements_run.txt misc/pygettext.py
	$(DISABLE_VENV) ; \
	virtualenv -p python2.7 .pyenv && \
	.pyenv/bin/pip install --upgrade pip && \
	.pyenv/bin/pip install cython==0.24.1 && \
	.pyenv/bin/pip install -r misc/requirements_run.txt
	cp misc/pygettext.py .pyenv/bin
	chmod +x .pyenv/bin/pygettext.py

apk: buildozer.spec .builddata/pyvirt .builddata/libs .builddata/p4a .builddata/bin/python .builddata/bin/cython .builddata/bin/pip compile-trans
	$(DISABLE_VENV) ; \
	export PYTHONPATH="$(CURDIR)/.builddata/pyvirt/lib/python2.7/site-packages:$${PYTHONPATH}" && \
	export PATH="$(CURDIR)/.builddata/bin:$${PATH}" && \
	python .builddata/pyvirt/bin/buildozer -v android debug

buildozer.spec: misc/buildozer.spec
	cp misc/buildozer.spec buildozer.spec

.builddata/bin/python:
	mkdir -p .builddata/bin
	$(DISABLE_VENV) ; \
	ln -s `which python2.7` .builddata/bin/python

.builddata/bin/cython: .builddata/pyvirt/bin/cython
	mkdir -p .builddata/bin
	$(DISABLE_VENV) ; \
	ln -s ../pyvirt/bin/cython .builddata/bin/cython

.builddata/bin/pip: .builddata/pyvirt/bin/pip
	mkdir -p .builddata/bin
	$(DISABLE_VENV) ; \
	echo "#!/bin/sh" > .builddata/bin/pip
	echo '$(CURDIR)/.builddata/pyvirt/bin/pip $$(echo $$@ | sed -e "s/--user//")' >> .builddata/bin/pip
	chmod +x .builddata/bin/pip

.builddata/p4a: misc/python-for-android-fix.patch
	mkdir -p .builddata
	rm -rf .builddata/p4a
	git clone https://github.com/kivy/python-for-android.git .builddata/p4a
	cd .builddata/p4a && patch -p1 < ../../misc/python-for-android-fix.patch

.builddata/libs: .builddata/zbar-android.zip
	rm -rf .builddata/libs
	rm -rf .builddata/ZBarAndroidSDK-*
	cd .builddata && unzip zbar-android.zip
	mv .builddata/ZBarAndroidSDK-*/libs .builddata/
	rm -rf .builddata/ZBarAndroidSDK-*

.builddata/zbar-android.zip:
	mkdir -p .builddata
	wget https://sourceforge.net/projects/zbar/files/AndroidSDK/ZBarAndroidSDK-0.2.zip/download -O .builddata/zbar-android.zip

.builddata/pyvirt .builddata/pyvirt/bin/cython .builddata/pyvirt/bin/pip: misc/requirements_build.txt
	mkdir -p .builddata
	rm -rf .builddata/pyvirt
	$(DISABLE_VENV) ; \
	virtualenv -p python2.7 .builddata/pyvirt && \
	.builddata/pyvirt/bin/pip install -r misc/requirements_build.txt && \
	.builddata/pyvirt/bin/pip install https://github.com/kivy/buildozer/archive/master.zip

clean:
	rm -rf __pycache__
	rm -f *.pyc
	rm -rf librksv/__pycache__
	rm -f librksv/*.pyc
	rm -rf librksv/test/__pycache__
	rm -f librksv/test/*.pyc
	rm -f lang/rktool.pot
	rm -f lang/*/LC_MESSAGES/rktool.mo
	rm -f aesBase64*.txt
	rm -f cert_*.key cert_*.crt cert_*.pub
	rm -f buildozer.spec

dist-clean: clean
	rm -rf .builddata
	rm -rf .buildozer
	rm -rf .pyenv

.PHONY: clean dist-clean setup update-trans compile-trans apk env

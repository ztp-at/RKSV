LANGS			= de
TURNOVER_COUNTER_SIZES	= 5,8,16
TEST_FILES		= $(shell find tests/ -name '*.json' | sort)

setup: aesBase64_1.txt cert_1.key cert_1.crt cert_1.pub

test: cert_1.key cert_1.crt cert_1.pub
	python2.7 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 2' $(TEST_FILES)
	command -v python3 >/dev/null 2>&1 && \
		python3 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 3' $(TEST_FILES)

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
	pygettext.py -o lang/rktool.pot *.py *.kv

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
	.pyenv/bin/pip install cython==0.21.2 && \
	.pyenv/bin/pip install -r misc/requirements_run.txt
	cp misc/pygettext.py .pyenv/bin

apk: buildozer.spec .builddata/pyvirt .builddata/libs .builddata/p4a .builddata/bin/python compile-trans
	$(DISABLE_VENV) ; \
	export PYTHONPATH="$(CURDIR)/.builddata/pyvirt/lib/python2.7/site-packages:$${PYTHONPATH}" && \
	export PATH=".builddata/bin:$${PATH}" && \
	LD_PRELOAD=/lib/libutil.so.1 .builddata/pyvirt/bin/buildozer -v android_new debug

buildozer.spec: misc/buildozer.spec
	cp misc/buildozer.spec buildozer.spec

.builddata/bin/python:
	mkdir -p .builddata/bin
	$(DISABLE_VENV) ; \
	ln -s `which python2.7` .builddata/bin/python

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

.builddata/pyvirt: misc/requirements_build.txt
	mkdir -p .builddata
	rm -rf .builddata/pyvirt
	$(DISABLE_VENV) ; \
	virtualenv -p python2.7 .builddata/pyvirt && \
	.builddata/pyvirt/bin/pip install -r misc/requirements_build.txt && \
	.builddata/pyvirt/bin/pip install https://github.com/kivy/buildozer/archive/master.zip

clean:
	rm -rf __pycache__
	rm -f *.pyc
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

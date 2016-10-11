LANGS			= de
TURNOVER_COUNTER_SIZES	= 5,8,16
TEST_FILES		= $(shell find tests/ -name '*.json' | sort)

setup: aesBase64_1.txt cert_1.key cert_1.crt cert_1.pub

test: cert_1.key cert_1.crt cert_1.pub
	python3 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 3' $(TEST_FILES) && \
	python2 ./test_verify.py multi cert_1.key cert_1.crt cert_1.pub $(TURNOVER_COUNTER_SIZES) 'Python 2' $(TEST_FILES)

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

apk: .builddata/pyvirt/bin/buildozer .builddata/libs .builddata/p4a .builddata/bin/python compile-trans
	PATH=".builddata/bin:${PATH}" LD_PRELOAD=/lib/libutil.so.1 .builddata/pyvirt/bin/buildozer -v android_new debug

.builddata/bin/python:
	mkdir -p .builddata/bin
	ln -s `which python2` .builddata/bin/python

.builddata/p4a: patches/python-for-android-fix.patch
	mkdir -p .builddata
	rm -rf .builddata/p4a
	git clone https://github.com/kivy/python-for-android.git .builddata/p4a
	cd .builddata/p4a && patch -p1 < ../../patches/python-for-android-fix.patch

.builddata/libs: .builddata/zbar-android.zip
	rm -rf .builddata/libs
	rm -rf .builddata/ZBarAndroidSDK-*
	cd .builddata && unzip zbar-android.zip
	mv .builddata/ZBarAndroidSDK-*/libs .builddata/
	rm -rf .builddata/ZBarAndroidSDK-*

.builddata/zbar-android.zip:
	mkdir -p .builddata
	wget https://sourceforge.net/projects/zbar/files/AndroidSDK/ZBarAndroidSDK-0.2.zip/download -O .builddata/zbar-android.zip

.builddata/pyvirt/bin/buildozer:
	mkdir -p .builddata
	rm -rf .builddata/pyvirt
	virtualenv -p python2 .builddata/pyvirt
	.builddata/pyvirt/bin/pip install https://github.com/kivy/buildozer/archive/master.zip

clean:
	rm -rf __pycache__
	rm -f *.pyc
	rm -f lang/rktool.pot
	rm -f lang/*/LC_MESSAGES/rktool.mo
	rm -f aesBase64*.txt
	rm -f cert_*.key cert_*.crt cert_*.pub

dist-clean: clean
	rm -rf .builddata
	rm -rf .buildozer

.PHONY: clean dist-clean setup update-trans compile-trans apk

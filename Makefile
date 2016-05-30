LANGS	= de

setup: aesBase64_1.txt cert_1.key cert_1.crt cert_1.pub

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

clean:
	rm -rf __pycache__
	rm -f *.pyc
	rm -f lang/rktool.pot
	rm -f lang/*/LC_MESSAGES/rktool.mo
	rm -f aesBase64*.txt
	rm -f cert*.key cert*.crt cert*.pub

.PHONY: clean setup update-trans compile-trans

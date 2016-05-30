trans-de: lang/de/LC_MESSAGES/rktool.mo

update-de: lang/de/LC_MESSAGES/rktool.po

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
	rm -f lang/rktool.pot
	rm -f lang/*/LC_MESSAGES/rktool.mo

.PHONY: clean trans-de update-de

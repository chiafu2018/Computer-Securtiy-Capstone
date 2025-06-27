all: attacker_server crack_attack

attacker_server: attacker_server.py
	@cp $< $@
	@chmod +x $@

crack_attack: crack_attack.py
	@cp $< $@
	@chmod +x $@

clean:
	@rm -f attacker_server crack_attack malicious_echo
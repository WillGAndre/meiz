.PHONY: capture deploy destroy clean

ENV ?= "en0"
TS := $(shell date +%Y-%m-%d_%H:%M:%S)

capture:
	@tcpdump -i $(ENV) -w capture/$(ENV)-$(TS).pcap -C 10 -W 5

deploy:
	@docker compose -f docker-compose.yaml up

destroy:
	@docker compose stop

clean:
	@rm capture/*.pcap[01234]
	@rm config/suricata_logs/*
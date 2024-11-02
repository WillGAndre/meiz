.PHONY: all clean build run deps


# tcpdump -i en0 -w config/capture.pcap -C 10 -W 5
deploy:
	@docker compose -f docker-compose.yaml up

destroy:
	@docker compose stop
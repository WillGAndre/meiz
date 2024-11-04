<pre>
    ▄▄▄▄███▄▄▄▄      ▄████████  ▄█   ▄███████▄  
  ▄██▀▀▀███▀▀▀██▄   ███    ███ ███  ██▀     ▄██ 
  ███   ███   ███   ███    █▀  ███▌       ▄███▀ 
  ███   ███   ███  ▄███▄▄▄     ███▌  ▀█▀▄███▀▄▄ 
  ███   ███   ███ ▀▀███▀▀▀     ███▌   ▄███▀   ▀ 
  ███   ███   ███   ███    █▄  ███  ▄███▀       
  ███   ███   ███   ███    ███ ███  ███▄     ▄█ 
  ▀█   ███   █▀    ██████████ █▀    ▀████████▀ 

               <i>Q&D Packet Sniffer</i>

  Replay network traffic from <i>tcpdump</i> via 
  <i>suricata</i> for visualization in <i>grafana</i> through
  <i>loki</i>/<i>promtail</i> integration.

      <u>Requirements</u>:
        - docker compose
        - make
        - golang (opt)

      <u>Usage</u>:
        Config: `.env`
        <b>One-off</b>: `go run meiz.go`
        Manual:
          1) `make capture ITF=$$$`
          2) `make deploy`

      <u>Grafana</u>: `http://127.0.0.1:3000/`
</pre>
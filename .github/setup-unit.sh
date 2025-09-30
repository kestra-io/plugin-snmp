docker compose -f docker-compose-ci.yml up -d
until docker logs snmptrapd 2>&1 | grep -q "NET-SNMP version"; do
  sleep 2
done

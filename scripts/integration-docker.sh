#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  compose)
    project=${CAPHE_COMPOSE_PROJECT:-caphe-local-compose}
    api=$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=api)
    workers=$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=worker)
    port=8787
    ;;
  swarm)
    stack=${CAPHE_SWARM_STACK:-caphe-local}
    api=$(docker ps -q --filter "label=com.docker.swarm.service.name=${stack}_api")
    workers=$(docker ps -q --filter "label=com.docker.swarm.service.name=${stack}_worker")
    port=8788
    ;;
  *) echo 'usage: integration-docker.sh compose|swarm' >&2; exit 1 ;;
esac
[[ -n "$api" && -n "$workers" ]] || { echo 'API and worker must be running locally' >&2; exit 1; }
api_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$api")
docker exec "$api" timeout 5 bash -c "echo > /dev/tcp/$api_ip/8787"
for worker in $workers; do
  set +e
  docker exec "$worker" timeout 5 bash -c "echo > /dev/tcp/$api_ip/8787"
  status=$?
  set -e
  if [[ "$status" != 124 && "$status" != 1 ]]; then
    echo "Worker network isolation failed (exit $status)" >&2
    exit 1
  fi
done
CAPHE_TEST_ENDPOINT="http://127.0.0.1:$port" go test ./tests/deployments -count=1 -v -timeout=10m

#!/bin/bash
# Initialize Redis Cluster

docker-compose -f docker-compose.redis-cluster.yml up -d

sleep 5

# Create cluster with 3 masters and 3 replicas
docker exec redis-node-1 redis-cli --cluster create \
  redis-node-1:7001 \
  redis-node-2:7002 \
  redis-node-3:7003 \
  redis-node-4:7004 \
  redis-node-5:7005 \
  redis-node-6:7006 \
  --cluster-replicas 1

echo "Redis Cluster initialized"
echo "Cluster nodes: redis-node-1:7001, redis-node-2:7002, redis-node-3:7003"

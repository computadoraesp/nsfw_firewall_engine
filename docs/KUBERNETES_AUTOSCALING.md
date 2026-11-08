# Kubernetes Auto-scaling

Auto-scaling configuration for NSFW Firewall Engine on Kubernetes.

## Components
- Deployment: nsfw-firewall-deployment
- Service: nsfw-firewall-service
- Horizontal Pod Autoscaler (HPA)
- ConfigMap: engine-config
- Secret: api-keys

## HPA Configuration
Scale based on CPU utilization:
- Min replicas: 2
- Max replicas: 10
- Target CPU: 70%
- Target memory: 80%

## Implementation
Create k8s/ directory with:
- deployment.yaml
- service.yaml
- hpa.yaml
- configmap.yaml
- secret.yaml

Status: Documentation completed, implementation pending (~4 hours)

3) Build + run
Build image

From your P2 service folder:

docker build -t ejwks:0.1 .

If you’re using kind
kind load docker-image ejwks:0.1


Then in k8s/ejwks.yaml set:

image: ejwks:0.1
imagePullPolicy: IfNotPresent

If you’re using a real cluster (or minikube without load)

Push to DockerHub/GHCR and set:

image: yourdockerhub/ejwks:0.1

Apply Kubernetes
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/ejwks-pvc.yaml
kubectl apply -f k8s/ejwks-config.yaml
kubectl apply -f k8s/ejwks.yaml


Check:

kubectl -n quitty get pods
kubectl -n quitty logs deploy/ejwks

4) Quick test (port-forward)
kubectl -n quitty port-forward svc/ejwks 8000:8000


Now in another terminal:

Health
curl http://127.0.0.1:8000/health

Import a key
curl -X POST http://127.0.0.1:8000/internal/keys/import \
  -H "Content-Type: application/json" \
  -d '{
    "kid": "demo-ed25519-1",
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "alg": "EdDSA"
  }'

Get root
curl http://127.0.0.1:8000/jwks/root

5) Why PVC is mandatory for your “pinned key” demo

Your client pins the root public key.

If the pod restarts and regenerates a new root key → pinned key breaks.

PVC keeps /data/root_signer_key.json stable across restarts.

So PVC = stable trust anchor.
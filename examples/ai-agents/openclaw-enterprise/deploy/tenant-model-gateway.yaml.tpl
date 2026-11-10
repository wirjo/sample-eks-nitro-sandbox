apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: OCE_TENANT_NAMESPACE
spec:
  podSelector: {}
  policyTypes:
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: OCE_TENANT_NAMESPACE
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-agentgateway
  namespace: OCE_TENANT_NAMESPACE
spec:
  podSelector:
    matchExpressions:
      - key: openclaw.dev/workload-role
        operator: In
        values:
          - agent
          - gateway
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: OCE_AGENTGATEWAY_SERVICE_CIDR
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: openclaw-enterprise-agw
          podSelector:
            matchLabels:
              app.kubernetes.io/name: agentgateway
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 4000

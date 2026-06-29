import os, sys
sys.path.insert(0, "E:\\compliance-agent")
os.environ["K8S_MCP_URL"] = "http://a791c074d8-cn.pods.criterionnetworks.com:20743/sse"
os.environ["USE_MOCK_DATA"] = "false"

from tools.kubernetes_tools import mcp

raw = mcp("pods_exec", {
    "namespace": "kube-system",
    "name": "kube-apiserver-k8s1",
    "command": ["sh", "-c", "cat /var/lib/rancher/rke2/server/db/etcd/config"]
})
print(repr(raw))
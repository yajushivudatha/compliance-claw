from tools.kubernetes_tools import (
    check_api_server_configuration,
    check_etcd_configuration,
    check_rbac_configuration,
    check_pod_security_configuration
)

print("\n" + "="*60)
print("TESTING ALL 4 KUBERNETES TOOLS")
print("="*60)

tools = [
    check_api_server_configuration,
    check_etcd_configuration,
    check_rbac_configuration,
    check_pod_security_configuration
]

for tool in tools:
    result = tool.invoke({})
    print(f"\n✅ {result['section']}")
    print(f"   Checks: {result['total_checks']} | "
          f"Passed: {result['passed']} | "
          f"Failed: {result['failed']}")
    for f in result['findings']:
        icon = "✅" if f['status'] == "PASS" else "❌"
        print(f"   {icon} [{f['control_id']}] {f['control_name']}")

print("\n" + "="*60)
print("ALL TOOLS WORKING")
print("="*60)
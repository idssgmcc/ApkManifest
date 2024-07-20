import xml.etree.ElementTree as ET
import argparse
from colorama import init, Fore, Style
import pyfiglet

# 初始化colorama
init(autoreset=True)

def print_title():
    title = pyfiglet.figlet_format("KhanTeam")
    print(Fore.CYAN + title + Style.RESET_ALL)

def print_banner():
    banner = """
                                        -   Khan安全团队
    """
    print(Fore.GREEN + banner + Style.RESET_ALL)

def check_permissions(root, issues):
    unnecessary_permissions = [
        "android.permission.READ_SMS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION"
    ]
    for permission in root.findall("uses-permission"):
        name = permission.get("{http://schemas.android.com/apk/res/android}name")
        if name in unnecessary_permissions:
            issues.append({
                "issue": f"发现不必要的权限: {name}",
                "description": "请求不必要的权限会增加应用的攻击面。",
                "severity": "中",
                "recommendation": "从清单中删除不必要的权限。",
                "code": ET.tostring(permission, encoding='unicode')
            })

def check_exported_components(root, issues):
    for component in root.findall(".//*[@android:exported='true']", namespaces={'android': 'http://schemas.android.com/apk/res/android'}):
        issues.append({
            "issue": f"发现导出的组件: {component.tag} 名称 {component.get('{http://schemas.android.com/apk/res/android}name')}",
            "description": "导出的组件可以被其他应用访问，可能导致敏感数据泄露或未经授权的操作。",
            "severity": "高",
            "recommendation": "将不需要被其他应用访问的组件的exported属性设置为false。",
            "code": ET.tostring(component, encoding='unicode')
        })

def check_debuggable(root, issues):
    application = root.find("application")
    if application is not None:
        debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable")
        if debuggable == "true":
            issues.append({
                "issue": "调试模式已启用",
                "description": "在生产环境中启用调试模式会暴露敏感信息并增加攻击风险。",
                "severity": "高",
                "recommendation": "在发布应用之前禁用调试模式。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_network_security_config(root, issues):
    application = root.find("application")
    if application is not None:
        network_security_config = application.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig")
        if network_security_config is not None:
            issues.append({
                "issue": "发现网络安全配置",
                "description": "确保网络安全配置强制使用HTTPS。",
                "severity": "中",
                "recommendation": "检查网络安全配置以确保强制使用HTTPS。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_backup(root, issues):
    application = root.find("application")
    if application is not None:
        allow_backup = application.get("{http://schemas.android.com/apk/res/android}allowBackup")
        if allow_backup == "true":
            issues.append({
                "issue": "允许备份已启用",
                "description": "启用备份可能导致敏感数据被备份到云端，增加数据泄露的风险。",
                "severity": "中",
                "recommendation": "禁用备份或确保敏感数据不被备份。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_file_provider(root, issues):
    for provider in root.findall("application/provider"):
        if provider.get("{http://schemas.android.com/apk/res/android}name") == "androidx.core.content.FileProvider":
            exported = provider.get("{http://schemas.android.com/apk/res/android}exported")
            if exported == "true":
                issues.append({
                    "issue": "FileProvider已导出",
                    "description": "导出FileProvider可能导致文件被未经授权访问。",
                    "severity": "高",
                    "recommendation": "将FileProvider的exported属性设置为false。",
                    "code": ET.tostring(provider, encoding='unicode')
                })

def check_custom_permissions(root, issues):
    for permission in root.findall("permission"):
        protection_level = permission.get("{http://schemas.android.com/apk/res/android}protectionLevel")
        if protection_level == "normal":
            issues.append({
                "issue": f"发现自定义权限，保护级别为normal: {permission.get('{http://schemas.android.com/apk/res/android}name')}",
                "description": "保护级别为normal的自定义权限可以被其他应用轻易授予，可能导致滥用。",
                "severity": "中",
                "recommendation": "为自定义权限使用更高的保护级别，例如signature。",
                "code": ET.tostring(permission, encoding='unicode')
            })

def check_webview_safe_browsing(root, issues):
    for activity in root.findall("application/activity"):
        for meta_data in activity.findall("meta-data"):
            if meta_data.get("{http://schemas.android.com/apk/res/android}name") == "android.webkit.WebView.EnableSafeBrowsing":
                if meta_data.get("{http://schemas.android.com/apk/res/android}value") == "false":
                    issues.append({
                        "issue": "WebView安全浏览已禁用",
                        "description": "禁用WebView安全浏览会增加钓鱼和恶意软件攻击的风险。",
                        "severity": "高",
                        "recommendation": "启用WebView安全浏览。",
                        "code": ET.tostring(meta_data, encoding='unicode')
                    })

def check_intent_filters(root, issues):
    for activity in root.findall("application/activity"):
        for intent_filter in activity.findall("intent-filter"):
            for action in intent_filter.findall("action"):
                if action.get("{http://schemas.android.com/apk/res/android}name") == "android.intent.action.VIEW":
                    issues.append({
                        "issue": f"在活动中发现未受保护的Intent过滤器: {activity.get('{http://schemas.android.com/apk/res/android}name')}",
                        "description": "未受保护的Intent过滤器可能被恶意应用利用来启动活动。",
                        "severity": "中",
                        "recommendation": "使用适当的权限保护Intent过滤器。",
                        "code": ET.tostring(intent_filter, encoding='unicode')
                    })

def check_sensitive_data_in_backup(root, issues):
    for meta_data in root.findall("application/meta-data"):
        if meta_data.get("{http://schemas.android.com/apk/res/android}name") == "android:fullBackupContent":
            issues.append({
                "issue": "检查是否在备份中排除了敏感数据",
                "description": "应排除敏感数据以防止未经授权的访问。",
                "severity": "中",
                "recommendation": "检查备份配置以确保排除了敏感数据。",
                "code": ET.tostring(meta_data, encoding='unicode')
            })

def check_task_and_launch_modes(root, issues):
    for activity in root.findall("application/activity"):
        launch_mode = activity.get("{http://schemas.android.com/apk/res/android}launchMode")
        if launch_mode in ["singleTask", "singleInstance"]:
            issues.append({
                "issue": f"发现具有潜在不安全启动模式的活动: {activity.get('{http://schemas.android.com/apk/res/android}name')} 启动模式 {launch_mode}",
                "description": "不安全的启动模式可能导致任务劫持和其他安全问题。",
                "severity": "中",
                "recommendation": "检查启动模式配置，并尽可能使用更安全的替代方案。",
                "code": ET.tostring(activity, encoding='unicode')
            })

def check_insecure_broadcast_receivers(root, issues):
    for receiver in root.findall("application/receiver"):
        exported = receiver.get("{http://schemas.android.com/apk/res/android}exported")
        if exported == "true":
            issues.append({
                "issue": f"发现不安全的BroadcastReceiver: {receiver.get('{http://schemas.android.com/apk/res/android}name')}",
                "description": "导出的BroadcastReceiver可以接收来自其他应用的广播，可能导致安全风险。",
                "severity": "高",
                "recommendation": "将不需要接收其他应用广播的BroadcastReceiver的exported属性设置为false。",
                "code": ET.tostring(receiver, encoding='unicode')
            })

def check_insecure_services(root, issues):
    for service in root.findall("application/service"):
        exported = service.get("{http://schemas.android.com/apk/res/android}exported")
        if exported == "true":
            issues.append({
                "issue": f"发现不安全的Service: {service.get('{http://schemas.android.com/apk/res/android}name')}",
                "description": "导出的Service可以被其他应用访问，可能导致安全风险。",
                "severity": "高",
                "recommendation": "将不需要被其他应用访问的Service的exported属性设置为false。",
                "code": ET.tostring(service, encoding='unicode')
            })

def check_insecure_content_providers(root, issues):
    for provider in root.findall("application/provider"):
        exported = provider.get("{http://schemas.android.com/apk/res/android}exported")
        if exported == "true":
            issues.append({
                "issue": f"发现不安全的ContentProvider: {provider.get('{http://schemas.android.com/apk/res/android}name')}",
                "description": "导出的ContentProvider可以被其他应用访问，可能导致数据泄露。",
                "severity": "高",
                "recommendation": "将不需要被其他应用访问的ContentProvider的exported属性设置为false。",
                "code": ET.tostring(provider, encoding='unicode')
            })

def check_insecure_activities(root, issues):
    for activity in root.findall("application/activity"):
        exported = activity.get("{http://schemas.android.com/apk/res/android}exported")
        if exported == "true":
            issues.append({
                "issue": f"发现不安全的Activity: {activity.get('{http://schemas.android.com/apk/res/android}name')}",
                "description": "导出的Activity可以被其他应用启动，可能导致安全风险。",
                "severity": "高",
                "recommendation": "将不需要被其他应用启动的Activity的exported属性设置为false。",
                "code": ET.tostring(activity, encoding='unicode')
            })

def check_insecure_meta_data(root, issues):
    for meta_data in root.findall("application/meta-data"):
        if meta_data.get("{http://schemas.android.com/apk/res/android}name") == "android:allowBackup":
            if meta_data.get("{http://schemas.android.com/apk/res/android}value") == "true":
                issues.append({
                    "issue": "在meta-data中启用了AllowBackup",
                    "description": "启用备份可能导致敏感数据被备份到云端，增加数据泄露的风险。",
                    "severity": "中",
                    "recommendation": "禁用备份或确保敏感数据不被备份。",
                    "code": ET.tostring(meta_data, encoding='unicode')
                })

def check_insecure_permissions(root, issues):
    for permission in root.findall("permission"):
        protection_level = permission.get("{http://schemas.android.com/apk/res/android}protectionLevel")
        if protection_level == "normal":
            issues.append({
                "issue": f"发现不安全的权限: {permission.get('{http://schemas.android.com/apk/res/android}name')} 保护级别 {protection_level}",
                "description": "保护级别为normal的权限可以被其他应用轻易授予，可能导致滥用。",
                "severity": "中",
                "recommendation": "为权限使用更高的保护级别，例如signature。",
                "code": ET.tostring(permission, encoding='unicode')
            })

def check_cleartext_traffic(root, issues):
    application = root.find("application")
    if application is not None:
        cleartext_traffic = application.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
        if cleartext_traffic == "true":
            issues.append({
                "issue": "允许明文流量",
                "description": "允许明文流量会增加数据被攻击者拦截的风险。",
                "severity": "高",
                "recommendation": "禁用明文流量并强制使用HTTPS。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_backup_agent(root, issues):
    application = root.find("application")
    if application is not None:
        backup_agent = application.get("{http://schemas.android.com/apk/res/android}backupAgent")
        if backup_agent is not None:
            issues.append({
                "issue": "配置了BackupAgent",
                "description": "使用BackupAgent时，确保敏感数据不被备份。",
                "severity": "中",
                "recommendation": "检查BackupAgent配置以确保敏感数据不被备份。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_allow_task_reparenting(root, issues):
    application = root.find("application")
    if application is not None:
        allow_task_reparenting = application.get("{http://schemas.android.com/apk/res/android}allowTaskReparenting")
        if allow_task_reparenting == "true":
            issues.append({
                "issue": "启用了AllowTaskReparenting",
                "description": "允许任务重新父化可能导致任务劫持和其他安全问题。",
                "severity": "中",
                "recommendation": "除非应用程序需要，否则禁用AllowTaskReparenting。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_allow_clear_user_data(root, issues):
    application = root.find("application")
    if application is not None:
        allow_clear_user_data = application.get("{http://schemas.android.com/apk/res/android}allowClearUserData")
        if allow_clear_user_data == "true":
            issues.append({
                "issue": "启用了AllowClearUserData",
                "description": "允许清除用户数据可能导致敏感数据被意外删除。",
                "severity": "中",
                "recommendation": "除非应用程序需要，否则禁用AllowClearUserData。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_large_heap(root, issues):
    application = root.find("application")
    if application is not None:
        large_heap = application.get("{http://schemas.android.com/apk/res/android}largeHeap")
        if large_heap == "true":
            issues.append({
                "issue": "启用了LargeHeap",
                "description": "启用large heap可能导致内存使用增加和潜在的性能问题。",
                "severity": "低",
                "recommendation": "除非应用程序需要，否则禁用LargeHeap。",
                "code": ET.tostring(application, encoding='unicode')
            })

def check_hardware_accelerated(root, issues):
    application = root.find("application")
    if application is not None:
        hardware_accelerated = application.get("{http://schemas.android.com/apk/res/android}hardwareAccelerated")
        if hardware_accelerated == "false":
            issues.append({
                "issue": "禁用了硬件加速",
                "description": "禁用硬件加速可能导致渲染性能问题。",
                "severity": "低",
                "recommendation": "启用硬件加速以提高性能。",
                "code": ET.tostring(application, encoding='unicode')
            })

def main():
    parser = argparse.ArgumentParser(description="检查AndroidManifest.xml中的安全问题。")
    args = parser.parse_args()

    manifest_file = "AndroidManifest.xml"
    tree = ET.parse(manifest_file)
    root = tree.getroot()

    issues = []

    checks = [
        check_permissions,
        check_exported_components,
        check_debuggable,
        check_network_security_config,
        check_backup,
        check_file_provider,
        check_custom_permissions,
        check_webview_safe_browsing,
        check_intent_filters,
        check_sensitive_data_in_backup,
        check_task_and_launch_modes,
        check_insecure_broadcast_receivers,
        check_insecure_services,
        check_insecure_content_providers,
        check_insecure_activities,
        check_insecure_meta_data,
        check_insecure_permissions,
        check_cleartext_traffic,
        check_backup_agent,
        check_allow_task_reparenting,
        check_allow_clear_user_data,
        check_large_heap,
        check_hardware_accelerated
    ]

    print_title()
    print_banner()

    total_checks = len(checks)

    for check in checks:
        check(root, issues)

    print(f"检测项数量: {total_checks}")
    print(f"检测到的漏洞数量: {len(issues)}\n")

    for issue in issues:
        severity_color = {
            "高": Fore.RED,
            "中": Fore.YELLOW,
            "低": Fore.GREEN
        }.get(issue['severity'], Fore.WHITE)

        print(severity_color + f"漏洞: {issue['issue']}")
        print(severity_color + f"描述: {issue['description']}")
        print(severity_color + f"等级: {issue['severity']}")
        print(severity_color + f"修复建议: {issue['recommendation']}")
        print(severity_color + f"代码:\n{issue['code']}")
        print(Style.RESET_ALL)

if __name__ == "__main__":
    main()

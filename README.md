# ApkManifest
人人有饭吃，人人会安卓。

安服仔一键水洞神器，apk反编译后提取AndroidManifest.xml文件，对AndroidManifest.xml进行漏洞检测

AndroidManifest.xml
check_ApkManifest.py

检查项：

        检查是否存在不必要的权限，这些权限可能会增加应用的攻击面。
        检查是否有导出的组件（Activity、Service、BroadcastReceiver、ContentProvider），这些组件可以被其他应用访问，可能导致敏感数据泄露或未经授权的操作。
        检查是否启用了调试模式，在生产环境中启用调试模式会暴露敏感信息并增加攻击风险。
        检查是否配置了网络安全配置，确保网络安全配置强制使用HTTPS。
        检查是否启用了允许备份，启用备份可能导致敏感数据被备份到云端，增加数据泄露的风险。
        检查FileProvider是否被导出，导出FileProvider可能导致文件被未经授权访问。
        检查自定义权限的保护级别，保护级别为normal的自定义权限可以被其他应用轻易授予，可能导致滥用。
        检查WebView是否启用了安全浏览，禁用WebView安全浏览会增加钓鱼和恶意软件攻击的风险。
        检查是否存在未受保护的Intent过滤器，未受保护的Intent过滤器可能被恶意应用利用来启动活动。
        检查是否在备份中排除了敏感数据，应排除敏感数据以防止未经授权的访问。
        检查Activity的启动模式，不安全的启动模式可能导致任务劫持和其他安全问题。
        检查是否存在不安全的BroadcastReceiver，导出的BroadcastReceiver可以接收来自其他应用的广播，可能导致安全风险。
        检查是否存在不安全的Service，导出的Service可以被其他应用访问，可能导致安全风险。
        检查是否存在不安全的ContentProvider，导出的ContentProvider可以被其他应用访问，可能导致数据泄露。
        检查是否存在不安全的Activity，导出的Activity可以被其他应用启动，可能导致安全风险。
        检查是否在meta-data中启用了AllowBackup，启用备份可能导致敏感数据被备份到云端，增加数据泄露的风险。
        检查是否存在不安全的权限配置，保护级别为normal的权限可以被其他应用轻易授予，可能导致滥用。
        检查是否允许明文流量，允许明文流量会增加数据被攻击者拦截的风险。
        检查是否配置了BackupAgent，使用BackupAgent时，确保敏感数据不被备份。
        检查是否启用了AllowTaskReparenting，允许任务重新父化可能导致任务劫持和其他安全问题。
        检查是否启用了AllowClearUserData，允许清除用户数据可能导致敏感数据被意外删除。
        检查是否启用了LargeHeap，启用large heap可能导致内存使用增加和潜在的性能问题。
        检查是否启用了硬件加速，禁用硬件加速可能导致渲染性能问题。

在终端或命令行中运行脚本：
    
      python3 check_manifest.py


![image](https://github.com/user-attachments/assets/2f5d4460-b9ce-45ac-888b-b36e85d4c750)

![image](https://github.com/user-attachments/assets/20f0a1a0-7330-40bb-a820-7209c3ce0893)


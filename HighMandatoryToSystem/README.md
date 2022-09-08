
## Usage
用于绕过UAC之后的administrator切换到System权限执行命令

- 通过`CreateProcessAsUser`执行命令：
  - `TokenManipulation.exe 1 <pid of winlogon.exe> "cmd /c whoami"`
- 通过`CreateProcessWithToken`执行命令，这种情况下不会有输出，可以弹个CMD
  -  `TokenManipulation.exe 2 <pid of winlogon.exe> "cmd"`

## 参考资料
- [Integrity Levels - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/integrity-levels)
- [通过复制Token提权到SYSTEM - idiotc4t's blog](https://idiotc4t.com/privilege-escalation/token-manipulation)
- [Why use CreateProcessAsUser instead of CreateProcessWithToken](https://github.com/itm4n/PrintSpoofer/issues/1)

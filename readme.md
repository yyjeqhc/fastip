# 使用:

```shell
fastpip -c config.tml
使用配置文件里面的多个dns服务器来解析配置文件里面的多个域名，最后通过ping得到单个域名响应最快的IP

子命令：
fastip ping -d ipAdrdr
直接ping某个IP地址

fastip lookup -s dnsserver -d domain
通过某个dns服务解析某个域名

fastip gendns -c config.txt -s dnsserver1 -s dnsserver2...
把一行一行的dns服务器转换为支持的配置文件格式

fastip genym -c config.txt -d domain1 -d domain
把一行一行的域名转换为支持的配置文件格式

fastpip -c config.tml test -s server1 -s server2 -d domain
让多个dns服务器来解析同一个域名，目的的判断这个dns服务器是否正常工作
```

# 未来：

目前的代码冗长又啰嗦，性能优化的地方也不少。比如：能监测某些域名的IP地址解析，例如现在有配置好的域名解析，使用软件重新找到了新的IP地址以及延迟，可以自动和原来解析的IP进行比较，合并为当前最快的IP，现在还没有支持，只能自己手动操作。

本意是因为校园网ipv6免费，ipv4计费，所以希望对某些支持ipv6的网站找到最快的IPV6访问地址。

但是，校园网下很多公共的DNS服务器不能正常提供服务。

如果有兴趣，欢迎提出issue和pr。
这是一个go 写的HTTP代理，

目前实现：
    
    - [x] 监听HTTPS
    - [x] 随机域名
    - [x] 访问不存在的域名达到次数封禁IP
    - [x] IP访问频率过高封禁IP

IP计数实现: `Redis`

封禁IP实现: `iptables`

具体用法自己摸索吧，加油 : )
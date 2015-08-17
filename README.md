# Snoopy-for-Python
翻译自一个强大的PHP采集库

By Doscript

原PHP库，详见
http://sourceforge.net/projects/snoopy/
# PHP版本的解释：
Snoopy是一个php类，用来模拟浏览器的功能，可以获取网页内容，发送表单。
Snoopy的特点：
1、抓取网页的内容 fetch
2、抓取网页的文本内容 (去除HTML标签) fetchtext
3、抓取网页的链接，表单 fetchlinks fetchform
4、支持代理主机
5、支持基本的用户名/密码验证
6、支持设置 user_agent, referer(来路), cookies 和 header content(头文件)
7、支持浏览器重定向，并能控制重定向深度
8、能把网页中的链接扩展成高质量的url(默认)
9、提交数据并且获取返回值
10、支持跟踪HTML框架
11、支持重定向的时候传递cookies
要求php4以上就可以了，由于本身是php一个类，无需扩支持，服务器不支持curl时候的最好选择。
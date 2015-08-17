# Snoopy-for-Python
<br>翻译自一个强大的PHP采集库

<br>By Doscript

*****
# PHP版本的解释：
<br>
原PHP库，详见<br>
http://sourceforge.net/projects/snoopy/<br>
Snoopy是一个php类，用来模拟浏览器的功能，可以获取网页内容，发送表单。<br>
Snoopy的特点：<br>
1、抓取网页的内容 fetch<br>
2、抓取网页的文本内容 (去除HTML标签) fetchtext<br>
3、抓取网页的链接，表单 fetchlinks fetchform<br>
4、支持代理主机<br>
5、支持基本的用户名/密码验证<br>
6、支持设置 user_agent, referer(来路), cookies 和 header content(头文件)<br>
7、支持浏览器重定向，并能控制重定向深度<br>
8、能把网页中的链接扩展成高质量的url(默认)<br>
9、提交数据并且获取返回值<br>
10、支持跟踪HTML框架<br>
11、支持重定向的时候传递cookies<br>
要求php4以上就可以了，由于本身是php一个类，无需扩支持，服务器不支持curl时候的最好选择。<br>

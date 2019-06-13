## OUC选课系统越权获取数据脚本 ##
### 主要功能 ###
- 查任何同学的成绩
-  选课专用
    1. 根据选课号查询选此课的人投的选课币
    2. 根据学号查询所有此学号的选课信息（包含2-1功能）
### 运行环境 ###
- Python3
   > pip3 install -r requirements.txt
- 安装tesseract-ocr
    1. Linux
        > sudo apt-get install tesseract-ocr
    2. Win
        下载tesseract-ocr，并配置pytesseract.pytesseract.tesseract_cmd为安装路径
### 配置文件 ###
config.json
学号和密码的md5值，首次使用需要输入
```json
{"username": "16020000000", "password_md5": "a8caa2688551c49a62a5574da0cd72f4"}
```
### 使用方式 ###
- 学号16020000000成绩
  
  python ouc-jwgl.py grades [username]
    > eg. python ouc-jwgl.py grades 16020000000 
    
- 2019夏季学期选课号为02003008的选课情况 0-夏季学期 1-秋季学期 2-春季学期
  
  python ouc-jwgl.py gamble_course [course_id] [year] [semester]
    > eg. python ouc-jwgl.py gamble_course 02003008 2019 2019-0


- 2019夏季学期学号为16020030000的选课情况
  
  python ouc-jwgl.py gamble_username [username] [year] [semester]
    > eg. python ouc-jwgl.py gamble_username 16020030000 2019 2019-0
    

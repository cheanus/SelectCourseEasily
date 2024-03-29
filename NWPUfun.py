import imaplib
import re
import time
import json
import email
import os
import requests
import hashlib
from lxml import etree
import numpy as np
import pandas as pd
import gurobipy as gp
from gurobipy import GRB


def get_color_code(text):
    ## 返回字符串映射的一个浅色颜色代码
    if text == '':
        return None
    else:
        # 使用MD5散列函数对文本进行哈希处理，获取唯一的16进制值
        hashed_text = hashlib.md5(text.encode()).hexdigest()
        red, green, blue = int(hashed_text[:2], 16), int(hashed_text[2:4], 16), int(hashed_text[4:6], 16)
        color_code = "#{:02x}{:02x}{:02x}".format(red%106+150, green%106+150, blue%106+105)
        return f'background-color: {color_code}'


class Nwpu:
    # 分割线内为应预设的信息
    #--------------------------------------------------
    # 翱翔门户安全邮箱地址
    sender = '123456789@qq.com'
    # 翱翔门户安全邮箱密码(部分邮箱为授权码，需开启IMAP协议)
    mail_pass = 'abcdefghigklmn'
    # 翱翔门户账户
    nwpu_username = '2021000000'
    # 翱翔门户账户
    nwpu_password = '123456789'
    # 条件组（年级、院系、专业、行政班级）
    category = ['2021', 'DL', '航空航天类', 'DL000000']
    #--------------------------------------------------

    headers = {
        'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif, '
            'image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'),
        'Accept-Encoding': 'deflate, br',
        'Accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Referer': 'https://ecampus.nwpu.edu.cn/main.html',
        'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'User-Agent': ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/103.0.0.0 Safari/537.36')
    }
    headers2 = headers.copy()
    headers2['X-Requested-With'] = 'XMLHttpRequest'
    headers2['Accept'] = 'application/json, text/javascript, */*; q=0.01'
    code_all = pd.Series([], dtype='object')
    solution_num = None
    data_all = None
    all_class_allowed = False
    
    
    def set_semester(self, text):
        # 将诸如“2022-2023春”的文字转化为学期代码
        response = self.session.get('https://jwxt.nwpu.edu.cn/student/for-std/lesson-search', headers=self.headers)
        semester = re.findall(r'value="(.*?)">'+text+r'</option>', response.text)
        if len(semester) == 0:
            raise Exception('学期输入格式错误')
        else:
            self.semester = str(semester[0])
    
    
    def login_nwpu(self):
        # 模拟登陆翱翔门户教务系统
        URL = ("https://uis.nwpu.edu.cn/cas/login?service=https%3A%2F%2Fecampus.nwpu.edu.cn"
           "%2F%3Fpath%3Dhttps%3A%2F%2Fecampus.nwpu.edu.cn")
        session = requests.session()
        if os.path.isfile('cookies.txt'):
            with open('cookies.txt', 'r', encoding='utf-8') as f:
                new_cookies = json.loads(f.read())
            session.cookies.update(new_cookies)
            response = session.get(URL, headers=self.headers)
            response.encoding = 'utf-8'
        else:
            response = session.get(URL, headers=self.headers)
            response.encoding = 'utf-8'
            str1 = re.search('var hmSiteId = "(.*?)"', response.text)
            new_cookies = {
                ("Hm_lvt_" + str1.group(1)): str(int(time.time())),
                ("Hm_lpvt_" + str1.group(1)): str(int(time.time()))
            }
            session.cookies.update(new_cookies)

        if len(response.history) == 0:
            #  没有重定向到主页，开始输入账号
            execution = re.search('name="execution" value="(.*?)"', response.text)

            URL = 'https://uis.nwpu.edu.cn/cas/mfa/detect'
            data = {
                'username': self.nwpu_username,
                'password': self.nwpu_password,
            }
            response = session.post(URL, data=data, headers=self.headers2)
            state_code = json.loads(response.text)['data']['state']

            URL = 'https://uis.nwpu.edu.cn/cas/mfa/initByType/secureemail?state=' + state_code
            response = session.get(URL, headers=self.headers2)
            gid = json.loads(response.text)['data']['gid']

            URL = 'https://uis.nwpu.edu.cn/attest/api/guard/secureemail/send'
            data = {'gid': gid}
            headers3 = self.headers2.copy()
            headers3['Content-Type'] = 'application/json; charset=UTF-8'
            session.post(URL, data=json.dumps(data), headers=headers3)

            # 获取邮件中的验证码

            conn = imaplib.IMAP4_SSL(host=r'imap.qq.com', port=993)
            code = conn.login(self.sender, self.mail_pass)

            for _ in range(3):
                time.sleep(7)
                conn.select()
                typ, data1 = conn.search(None, '(FROM "portal@nwpu.edu.cn")')
                try:
                    typ, data2 = conn.fetch(data1[0].decode().split()[-1], '(RFC822)')
                except IndexError as e:
                    continue
                msg = email.message_from_string(data2[0][1].decode('utf-8'))
                IDENTIFY_CODE = 0
                for part in msg.walk():
                    if not part.is_multipart():
                        CONTENT = part.get_payload(decode=True).decode('utf-8')
                        if CONTENT.startswith('您正在进行验证身份'):
                            IDENTIFY_CODE = CONTENT[14:18]
                            conn.store(data1[0].decode().split()
                                    [-1], "+FLAGS", "\\Deleted")
                            conn.expunge()
            conn.close()
            conn.logout()

            # 已经得到验证码，提交

            URL = 'https://uis.nwpu.edu.cn/attest/api/guard/secureemail/valid'
            data['code'] = IDENTIFY_CODE
            session.post(URL, data=json.dumps(data), headers=headers3)

            URL = ("https://uis.nwpu.edu.cn/cas/login?service=https%3A%2F%2Fecampus.nwpu.edu.cn"
                    "%2F%3Fpath%3Dhttps%3A%2F%2Fecampus.nwpu.edu.cn")
            data = {
                'username': self.nwpu_username,
                'password': self.nwpu_password,
                'rememberMe': 'true',
                'currentMenu': '1',
                'mfaState': state_code,
                'execution': execution.group(1),
                '_eventId': 'submit',
                'geolocation': '',
                'submit': '稍等片刻……',
            }
            response = session.post(URL, data=data, headers=self.headers)

        # 已经得到授权，保存cookies
        cookies = json.dumps(session.cookies.get_dict())
        with open('cookies.txt', 'w', encoding='utf-8') as f:
            f.write(cookies)

        # 进入教务系统
        URL = 'https://jwxt.nwpu.edu.cn/student/sso-login'
        session.get(URL, headers=self.headers)
        self.session = session


    def is_class_accept(self, class_id):
        if self.all_class_allowed:
            return True
        # 查看自己是否符合某个课的选课组要求
        response = self.session.get('https://jwxt.nwpu.edu.cn/student/for-std-lessons/info/' + class_id, headers=self.headers)
        response.encoding = 'utf-8'

        html = etree.HTML(response.text).xpath('/html/body/div/div/div/div[2]/div/div[2]/table[2]/tr[1]/td/table//td/text()')

        accept = True
        for i, j in enumerate([7, 22, 25, 31]):
            if html[j+1] == '包含' and self.category[i] not in html[j+2]:
                accept = False
                break
        return accept


    def class_schedule(self, course_code):
        # 输出示例：
        # (
        #   毛泽东思想和中国特色社会主义理论体系概论，
        #   (('U44G11026.01', '3~13周 周一 第七节~第八节; \n3~12周 周三 第七节~第八节'),
        #    ('U44G11026.02', '3~13周 周一 第九节~第十节; \n3~12周 周三 第九节~第十节'),
        #    ('U44G11026.03', '3~13周 周二 第一节~第二节; \n3~12周 周四 第一节~第二节'),
        #    ('U44G11026.04', '3~13周 周二 第七节~第八节; \n3~12周 周四 第七节~第八节'),
        #    ('U44G11026.05', '3~13周 周二 第三节~第四节; \n3~12周 周四 第三节~第四节'),
        #    ('U44G11026.06', '3~13周 周二 第九节~第十节; \n3~12周 周四 第九节~第十节'))
        #)
        url = 'https://jwxt.nwpu.edu.cn/student/for-std/lesson-search'
        response = self.session.get(url)
        identify_code = re.findall(r'index/(.*)', response.history[0].headers['Location'])[0]
        url = ('https://jwxt.nwpu.edu.cn/student/for-std/lesson-search/semester/' + self.semester + '/search/'+ identify_code
                + '?courseCodeLike=' + course_code
                + '&bizTypeAssoc=1&assembleFields=course.code%2CminorCourse.nameZh%2CcourseType%2CopenDepartment%2CteacherAssignmentList%2CexamMode%2Ccampus%2CteachLang%2CroomType%2CtimeTableLayout%2CcrossBizTypes%2CcourseProperty&_=1678425902146')
        response = json.loads(self.session.get(url, headers=self.headers2).text)
        course_data = response['data']
        name = course_data[0]['course']['nameZh']
        for current_page in range(2, response['_page_']['totalPages'] + 1):
            course_data.extend(json.loads(self.session.get(url + '&queryPage__=' + str(current_page) + ',20',
                                                      headers=self.headers2).text)['data'])

        course_data_filter = set()
        for class_ in course_data:
            if self.is_class_accept(str(class_['id'])):
                course_data_filter.add((class_['code'], class_['scheduleText']['dateTimePlacePersonText']['textZh']))

        return name, tuple(course_data_filter)


    def chinese2number(self, character):
        # 返回汉字的阿拉伯数形式
        match character:
            case '一':
                return 1
            case '二':
                return 2
            case '三':
                return 3
            case '四':
                return 4
            case '五':
                return 5
            case '六':
                return 6
            case '七' | '日':
                return 7
            case '八':
                return 8
            case '九':
                return 9
            case '十':
                return 10
            case '十一':
                return 11
            case '十二':
                return 12
            case '十三':
                return 13
            case _:
                return 13


    def text2array(self, text):
        # 将排课信息的文字描述转为array矩阵
        section = text.split('; \n')
        schedule = np.zeros((18, 7, 13), dtype=np.bool_)
        for s in section:
            # print(s)
            text_re1 = re.findall(r'^(.*?)周', s)[0].split(',')
            text_re2 = re.findall(r'周 周(.*?) 第(.*?)节(?:（中午）)?~第(.*?)节(?:（中午）)?', s)[0]
            
            week = []
            for x in text_re1:
                if '~' in x:
                    week_start, week_end = re.findall(r'(.*)~(.*)', x)[0]
                    week_start = int(week_start) - 1
                    week_end = int(week_end) - 1
                    week.extend(list(range(week_start, week_end+1)))
                else:
                    week.append(int(x) - 1)
            day, class_start, class_end = text_re2
            
            day = self.chinese2number(day) - 1
            class_start = self.chinese2number(class_start) - 1
            class_end = self.chinese2number(class_end) - 1

            for w in week:
                schedule[w, day, class_start:class_end+1] = True
        return schedule


    def short_word(self, string, limit, is_show_end):
        # 返回简短的文字
        if is_show_end:
            if len(string) > limit:
                return string[:limit//2] + '..' + string[-limit//2:]
            else:
                return string
        else:
            if len(string) > limit:
                return string[:limit]
            else:
                return string


    def collect_data(self):
        # 根据self.code_all，收集所选课程的所有排课信息
        if self.data_all is None:
            self.data_all = pd.DataFrame(columns=('code', 'name', 'No.', 'text'))
            self.schedule_data_all = []
        code_all_add = self.code_all[~self.code_all.isin(self.data_all.code)]
        for n, code in enumerate(code_all_add):
            print(f'正在提取{code}信息...({n+1}/{len(code_all_add)})', end='')
            name, texts = self.class_schedule(code)
            for sub_code, s in texts:
                self.data_all = pd.concat([self.data_all, pd.DataFrame([[code, name, sub_code, s]], columns=('code', 'name', 'No.', 'text'))])
                self.schedule_data_all.append(self.text2array(s))
            print('完毕')
        self.data_all = self.data_all.reset_index(drop=True)


    def part_course(self, code_consider=[]):
        # 根据code_consider，过滤不符合条件的课程
        if len(code_consider) == 0:
            code_consider = self.code_all.tolist()
        is_consider = (self.data_all['code'].isin(code_consider) | self.data_all['No.'].isin(code_consider))
        self.data_consider = self.data_all[is_consider]
        self.course_index = self.data_consider[['code', 'No.']]

        self.schedule_data_consider = np.array([self.schedule_data_all[i] for i in range(len(self.data_all)) if is_consider[i]])
        self.code_consider = [re.findall('^(.*?)(\.\d\d)*$', str(x))[0][0] for x in code_consider]
        
        
    def gurobi_modeling(self):
        ## 调用gurobi求解
        # 建立model
        m = gp.Model('schedule')
        # 设置多解参数
        if self.solution_num is not None:
            m.setParam(GRB.Param.PoolSolutions, self.solution_num)
            m.setParam(GRB.Param.PoolSearchMode, 2)
            
        # index为索引，形式如(('U01M13001', 'U01M13001.01'), ('U01M13001', 'U01M13001.02'))
        # 前者为课程代码，后者用以区分有不同排课时间的各教学班
        index = self.course_index.apply(lambda x: tuple(x), axis=1).values.tolist()
        # x是0-1决策变量，字典类型，键为index。1表示选上状态，0表示不选状态
        x = m.addVars(index, name='x', vtype=GRB.BINARY)
        # self.schedule_data_consider是一个n*18*7*13的0-1常数矩阵（n=len(index)，18表示1-18教学周数，7表示星期数，13表示一天的节数）
        # 1表示该课在该时间段上课，0表示该课在该时间段不上课
        # 基本约束
        m.addConstrs((x.values() @ self.schedule_data_consider[:,i,j,k] <= 1 for i in range(18) for j in range(7) for k in range(13)))  # 同一个时间段最多上一节课
        m.addConstrs((x.sum(str(h), '*') == 1 for h in self.code_consider))  # 每个课程代码都要选一门课

        # 自定义规则示例
        # m.addConstrs((x.values() @ schedule_data_consider[:,i,j,k] == 0 for i in range(16) for j in range(7) for k in range(2)))  # 没有早八
        # m.setObjective(np.sum(np.reshape(x.values(), (len(x),1,1,1)) * self.schedule_data_consider[:,:,:,:2]))  # 尽可能让早八次数最少
        # m.addConstrs((x.values() @ schedule_data_consider[:,i,j,k] == 0 for i in range(16) for j in range(5, 7) for k in range(13)))  # 没有周末课
        
        m.optimize()
        if m.Status == GRB.OPTIMAL:
            self.m = m
            self.x = x
            if self.solution_num is None:
                self.solution = m.getAttr('X', x)
                print('有解')
            else:
                print(f'有{m.SolCount}个解')
        else:
            print('无解')
    
            
    def graph(self, solution_i = 0, limit=4, is_show_end=False):
        # 绘制课表
        m = self.m
        if self.solution_num is not None:
            m.setParam(GRB.Param.SolutionNumber, solution_i)
            solution = m.getAttr('Xn', self.x)
        else:
            solution = self.solution
        
        course_table = self.data_consider[['code', 'name', 'text']][np.array(solution.values()) == 1].reset_index(drop=True)
        
        week_schedule_data = np.any(self.schedule_data_consider[np.array(solution.values()) == 1], axis=1)
        week_schedule_df = pd.DataFrame(np.empty((13,7), dtype=np.str_), columns=('周一', '周二', '周三', '周四', '周五', '周六', '周日'))
        for n, c in enumerate(week_schedule_data):
            for i, j in np.argwhere(c == 1):
                if week_schedule_df.iloc[j, i] != '':
                    week_schedule_df.iloc[j, i] += ';'
                week_schedule_df.iloc[j, i] += self.short_word(course_table.name[n], limit=limit, is_show_end=is_show_end)
         
        week_schedule_df.set_axis(np.arange(1, 14), axis=0)
        week_schedule_df = week_schedule_df.style.applymap(get_color_code)
        
        return course_table, week_schedule_df
    
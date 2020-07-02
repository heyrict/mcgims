import argparse
import os
from sys import exit
import re
import random
import time
from datetime import datetime, timedelta
from rich.logging import RichHandler

import requests
import logging
import yaml

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("rich")
logging.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO")))

HOST = "mcgims.njmu.edu.cn"
HOSTNAME = f"http://{HOST}"

RE_JSESSIONID = re.compile(r'(JSESSIONID)=([^;]+)')

EP_LOGIN = f"{HOSTNAME}/loginweb/loginbyusercodeandpass.action"
EP_LOGIN_ROLE = f"{HOSTNAME}/loginweb/loginbyauth.action"
EP_GET_TRAIN_TIME = f"{HOSTNAME}/configweb/getTrainTime.action"
EP_SAVE_HOL_ARRAY = f"{HOSTNAME}/configweb/saveHolArr.action"
EP_SAVE_HOL_ARRAY_T = f"{HOSTNAME}/configweb/saveHolArrT.action"
EP_SELECT_ATTEND_INFO = f"{HOSTNAME}/teachweb/selectStuAttendanceInfoList.action"
EP_MANAGE_ATTEND_STATE = f"{HOSTNAME}/teachweb/manageAttendState.action"

EP_VAPP_LOGIN = f"{HOSTNAME}/app/Vapp_login.action"

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "./config.yaml")


def sleep():
    time.sleep(random.random() * 2 + 1)


def get_session_id():
    """
    Get session id as http cookie
    """
    headers = {
        'Host': HOST,
        'Accept': 'text/html,application/xhtml+xml,application/xml, */*; q=0.01',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    } # yapf: disable

    response = requests.get(HOSTNAME, headers=headers)
    log.debug("In get_session_id():")
    log.debug("--> Request headers")
    log.debug(headers)
    log.debug("<-- Response status code")
    log.debug(response.status_code)
    log.debug("<-- Response headers")
    log.debug(response.headers)

    try:
        match = RE_JSESSIONID.match(response.headers['Set-Cookie'])
        return dict((match.groups(), ))
    except Exception as e:
        log.error("Unable to get session cookies:")
        log.error(e)
        raise e


def post_form(endpoint, data, cookies=None):
    """
    Helper function for posting urlencoded form
    """
    headers = {
        'Host': HOST,
        'Accept': 'application/json, */*; q=0.01',
        'Origin': HOSTNAME,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': HOSTNAME,
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    } # yapf: disable

    response = requests.post(
        endpoint, data=data, headers=headers, cookies=cookies
    )
    log.debug("In postform:")
    log.debug(f"- endpoint: {endpoint}")
    log.debug(f"- data: {data}")
    log.debug(f"- cookies: {cookies}")

    if response.status_code != 200:
        log.error(
            "post_form: {} POST {}".format(response.status_code, endpoint)
        )
        exit(1)
    response = response.json()
    log.debug(f"- response: {response}")
    if response.get('success') == False:
        log.error("Error posting form on endpoint {endpoint}:")
        log.error("Response:")
        log.error(response)
    return response


def get_form(endpoint, data=None, cookies=None):
    """
    Helper function for querying
    """
    headers = {
        'Host': HOST,
        'Accept': 'application/json, */*; q=0.01',
        'Origin': HOSTNAME,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': HOSTNAME,
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    } # yapf: disable

    response = requests.get(
        endpoint, params=data, headers=headers, cookies=cookies
    )
    log.debug("In get_form:")
    log.debug(f"- endpoint: {endpoint}")
    log.debug(f"- data: {data}")
    log.debug(f"- cookies: {cookies}")

    if response.status_code != 200:
        log.error("get_form: {} GET {}".format(response.status_code, endpoint))
        exit(1)
    response = response.json()
    log.debug(f"- response: {response}")
    if response.get('success') == False:
        log.error("Error posting form on endpoint {endpoint}:")
        log.error("Response:")
        log.error(response)
    return response


def auth(username, password, cookies=None):
    """
    用户登录

    # Returns
    - "token": （仅微信）authentication token
    - "role_code": 用户组 (enum)
        - "R_STU": 学生
        - "R_TEA": 带教老师
        - "R_KS_ADMIN": 教秘
    - "auth_id": 用户编号
    - "orga_id": 科室编号
    - "user_name": 用户名称
    - "user_password": 用户密码
    - “user_code": 用户名 (未返回)
    """
    res = post_form(
        EP_LOGIN, {
            'userCode': username,
            'password': password,
            'pHeight': 472,
            'pWidth': 1362,
        },
        cookies=cookies
    )
    login_type = res.get('loginType')

    if login_type == "1":
        # Student
        res = get_form(
            EP_VAPP_LOGIN,
            data={
                'usercode': username,
                'password': password,
            },
            cookies=cookies
        )
        roles = res['vList']
        if len(roles) == 0:
            returns = {}
        else:
            role = roles[0]
            returns = {
                'token': res.get('token'),
                'role_code': role.get('role_code', 'R_STU'),
                'auth_id': role.get('auth_id'),
                'orga_id': role.get('orga_id'),
                'user_id': role.get('user_id'),
                'user_name': role.get('user_name'),
                'user_password': role.get('user_password'),
            }

    elif login_type == "2":
        # Teacher
        auth_list = res.get('authList')

        admin_list = [
            a for a in auth_list if a.get("role_code") == "R_KS_ADMIN"
        ]

        if len(admin_list) == 0:
            log.error("auth: NOT_IMPLEMENTED Unable to find admin role")
            log.error(f"Response: {res}")
            exit(1)

        admin_role = admin_list[0]

        returns = {
            'role_code': admin_role.get('role_code'),
            'auth_id': admin_role.get('auth_id'),
            'orga_id': admin_role.get('orga_id'),
            'user_id': admin_role.get('user_id'),
            'user_name': admin_role.get('user_name'),
            'user_password': admin_role.get('user_password'),
        }

        post_form(
            EP_LOGIN_ROLE, {
                'authId': returns['auth_id'],
                'pHeight': 460,
                'pWidth': 895,
            },
            cookies=cookies
        )
    else:
        log.error("Unrecognised login type")
        return {}

    return returns


def get_train_time(cookies=None):
    """
    （学生）获取入科出科时间

    # Returns
    - "start": 入科时间,
    - "end": 出科时间,
    """
    res = post_form(EP_GET_TRAIN_TIME, {}, cookies=cookies)
    rows = res["rows"]
    return {
        'start': rows['train_start_time']['time'] // 1000,
        'end': rows['train_end_time']['time'] // 1000,
    }


def save_hol_arr(arr, cookies=None):
    """
    （学生）提交排班申请

    # Parameters
    - arr: 上班日期的列表, 日期格式为 "%Y%m%d", e.g. ["20200630", "20200701"]
    """
    res = post_form(EP_SAVE_HOL_ARRAY, {
        'array': arr,
    }, cookies=cookies)


def save_hol_arr_t(cookies=None):
    """
    （教师）审核排班申请
    """
    res = post_form(EP_SAVE_HOL_ARRAY_T, {
        'array': None,
    }, cookies=cookies)


def init_schedule(cookies=None):
    """
    （学生）上传缺省排班情况（周一至周五上班）。初次入科时使用。
    """
    dates = get_train_time(cookies=cookies)
    start = datetime.fromtimestamp(dates['start'])
    end = datetime.fromtimestamp(dates['end'])

    array = []
    cur = start
    while cur < end:
        # Monday to Friday
        if cur.weekday() <= 4:
            array.append(cur.strftime("%Y%m%d"))
        cur += timedelta(days=1)

    save_hol_arr(array, cookies=cookies)


def select_attend_info(cookies=None):
    """
    （教师）获取当日出勤情况

    # Returns
    An array of the following object
    - "stu_auth_id": 学生编号
    - "id": 轮转编号？
    - "attend_state": 出勤情况 (enum)
        - 1: 已考勤
        - 4: 放假
    """
    res = post_form(
        EP_SELECT_ATTEND_INFO, {
            'attend_state': 3,
        }, cookies=cookies
    )

    return [
        {
            'stu_auth_id': data.get('stu_auth_id'),
            'id': data.get('id'),
            'attend_state': data.get('attend_state'),
        } for data in res['data']
    ]


def manage_attend_state(
    gid, student_id, date=datetime.now(), attend_state=1, cookies=None
):
    """
    （教师）更新学生出勤情况

    # Parameters
    - gid: 轮转编号？
    - student_id: 即 `stu_auth_id`, 学生编号
    - date: 出勤日期 (datetime object or `%Y-%m-%d` styled string)
    - attend_state: 更新后出勤情况。见 select_attend_info
    """
    if isinstance(date, datetime):
        date = datetime.strftime("%Y-%m-%d")

    res = post_form(
        EP_MANAGE_ATTEND_STATE, {
            'id': gid,
            'stu_auth_id': student_id,
            'attend_state': attend_state,
            'this_day': date,
        },
        cookies=cookies
    )


def get_config(file_path="./config.yaml"):
    """
    Read config file from `file_path`.

    The schema of the config file:

    ```typescript
    type Config = {
        student: {
            username: string,
            password: string,
        },
        admin: {
            username: string,
            password: string,
        },
    }
    ```
    """
    if not os.path.exists(file_path):
        log.error(f"Error opening file `{file_path}`")
        exit(1)

    with open(file_path) as f:
        config = yaml.load(f)

    return config


class Actions:
    INIT_SCHEDULE = "INIT_SCHEDULE"
    CONFIRM_SCHEDULE = "CONFIRM_SCHEDULE"
    ATTEND_TODAY = "ATTEND_TODAY"
    ATTEND_TODAY_ALL = "ATTEND_TODAY_ALL"

    @classmethod
    def choices(cls):
        return [
            cls.INIT_SCHEDULE,
            cls.CONFIRM_SCHEDULE,
            cls.ATTEND_TODAY,
        ]


def main():
    parser = argparse.ArgumentParser(
        description="CLI for managing mcgims.njmu.edu.cn"
    )
    parser.add_argument(
        '-c',
        '--config',
        dest="config_file",
        default=CONFIG_FILE,
        help="Path to the config file",
        type=str
    )
    parser.add_argument("action", choices=Actions.choices())

    args = parser.parse_args()
    config_file = args.config_file

    config = get_config(config_file)

    if args.action == Actions.INIT_SCHEDULE:
        st_cookies = get_session_id()
        st_info = auth(
            config['student']['username'],
            config['student']['password'],
            cookies=st_cookies
        )
        init_schedule(st_cookies)
    if args.action == Actions.CONFIRM_SCHEDULE:
        ad_cookies = get_session_id()
        ad_info = auth(
            config['admin']['username'],
            config['admin']['password'],
            cookies=ad_cookies
        )
        save_hol_arr_t(cookies=ad_cookies)
    if args.action == Actions.ATTEND_TODAY:
        st_cookies = get_session_id()
        st_info = auth(
            config['student']['username'],
            config['student']['password'],
            cookies=st_cookies
        )
        ad_cookies = get_session_id()
        ad_info = auth(
            config['admin']['username'],
            config['admin']['password'],
            cookies=ad_cookies
        )
        attend_list = select_attend_info(cookies=ad_cookies)
        st_attend_infos = [
            a for a in attend_list
            if a.get('stu_auth_id') == st_info['auth_id']
        ]
        if len(st_attend_infos) == 0:
            log.error(
                f"Error finding user {st_info['user_name']} in the group"
            )
            exit(1)
        st_attend_info = st_attend_infos[0]
        if st_attend_info.get("attend_state") == 1:
            log.warning(
                f"User {st_info['user_name']} is already attended today"
            )
        else:
            manage_attend_state(
                st_attend_info["id"], st_info['auth_id'], cookies=ad_cookies
            )
    if args.action == Actions.ATTEND_TODAY_ALL:
        ad_cookies = get_session_id()
        ad_info = auth(
            config['admin']['username'],
            config['admin']['password'],
            cookies=ad_cookies
        )
        attend_list = select_attend_info(cookies=ad_cookies)
        for attend in attend_list:
            if attend.get("attend_state") == 1:
                log.warning(
                    f"User {st_info['user_name']} is already attended today"
                )
            else:
                manage_attend_state(
                    attend["id"], st_info['auth_id'], cookies=ad_cookies
                )


if __name__ == "__main__":
    main()

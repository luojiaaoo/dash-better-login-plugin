from dash import hooks, dcc, set_props, Input, Output, State
import dash
import jwt
from flask import request,redirect,make_response,abort
from yarl import URL
import feffery_utils_components as fuc
from typing import Callable, Optional, Tuple, Dict
from uuid import uuid4
from datetime import datetime, timezone, timedelta

PACKAGE_NAME = 'dash-better-login-plugin'
JWT_SERCRET = 'C3Rr0MFPcO9Pd4UGqejcRigJx1rqjY20fEArXiGYvNnh4jkzAuLyfLkkOghBbDAU'

store_trigger_login = dcc.Store(id=f'{PACKAGE_NAME}/trigger-login')
store_trigger_login_fail_message = dcc.Store(id=f'{PACKAGE_NAME}/trigger-login-fail-message')


def trigger_login(user: str, password: str):
    """触发登录事件，设置store的值"""
    set_props(store_trigger_login.id, {'data': {'uuid4': uuid4().hex, 'user': user, 'password': password}})


def get_input_login_fail_message():
    """获取登录失败消息的输出组件，与登录输入框提示建立对应回调关系"""
    return Input(store_trigger_login_fail_message, 'data')


def setup_better_login_plugin(
    login_page_pathname: str,  # 登录页面的路径
    logout_page_pathname: str,  # 登出页面的路径，登出成功后跳转到该页面
    main_page_pathname: str,  # 主页面的路径，登录成功后跳转到该页面
    verify_handler: Callable[[str, str], Tuple[bool, Optional[str]]],  # 判断验证用户名和密码的处理函数
    jwt_exp_seconds: int = 3600 * 12,  # JWT过期时间，单位为秒，默认12小时
    jwt_save_dict_handler: Optional[Callable[[str], Dict]] = None,  # 保存用户登录状态的处理函数，返回一个字典，包含需要保存到cookie的jwt内容
    jwt_secret: str = None,  # JWT密钥解密cookie和auth bearer 请求头，用于判断用户是否已经登录
) -> None:
    """
    注入登录相关handlers处理函数
    """
    if jwt_secret is None:
        jwt_secret = JWT_SERCRET
    else:
        global JWT_SERCRET
        JWT_SERCRET = jwt_secret

    @hooks.layout()
    def update_layout(layout):
        """注入layout"""
        components = [fuc.FefferyLocation(id=f'{PACKAGE_NAME}/global-get-location'), fuc.FefferyExecuteJs(id=f'{PACKAGE_NAME}/global-execute-js-output')]
        if isinstance(layout, list):
            return [components, *layout]
        return [components, layout]

    @hooks.callback(
        Output(f'{PACKAGE_NAME}/global-execute-js-output', 'jsString'),
        Input(store_trigger_login, 'data'),
        State(f'{PACKAGE_NAME}/global-get-location', 'href'),
    )
    def callback_login(data: Dict, href):
        user = data.get('user')
        password = data.get('password')
        is_ok, message = verify_handler(user, password)
        if not is_ok:
            # 设置登录失败消息
            set_props(store_trigger_login_fail_message.id, {'data': message})
            return dash.no_update
        # 登录成功
        if jwt_save_dict_handler is None:
            jwt_save_dict = {'user': user}
        else:
            jwt_save_dict = jwt_save_dict_handler(user)
        to_encode = jwt_save_dict.copy()
        expire = datetime.now(timezone.utc) + timedelta(seconds=jwt_exp_seconds)
        to_encode.update({'exp': expire})
        encoded_jwt = jwt.encode(to_encode, jwt_secret, algorithm='HS256')
        # 持久化登录JWT凭证
        dash.ctx.response.set_cookie('Authorization', f'Bearer {encoded_jwt}', max_age=3600 * 24 * 365)
        # 读取当前页面的URL，如果有redirect参数，则读取该参数的值，并跳转回该页面
        if redirect_path := URL(href).query.get('redirect'):
            # 如果有redirect参数，则跳转到该页面
            return f"window.location.assign('{URL.build(path=redirect_path).__str__()}');"
        else:
            # 否则跳到主页
            return f"window.location.assign('{URL.build(path=main_page_pathname).__str__()}');"

    @hooks.route(name=logout_page_pathname.lstrip('/'))
    def route_logout():
        """强制登出，重定向到登录页面"""
        response = make_response(redirect(login_page_pathname))
        response.set_cookie('Authorization', '', expires=0)
        return response
    
    
    
    @hooks.route(name="")
    def route_root():
        """访问根路径，判断是否登录，如登录指向首页"""
        from jwt.exceptions import ExpiredSignatureError
        auth_header = token_ if (token_ := request.headers.get('Authorization')) else request.cookies.get('Authorization')
        if not auth_header:
            return redirect(login_page_pathname)
        auth_info = auth_header.split(' ', 1)
        if len(auth_info) != 2 or not auth_info[0].strip() or not auth_info[1].strip():
            abort(400)
        auth_type, auth_token = auth_info
        if auth_type == 'Bearer':
            # jwt验证
            try:
                payload = jwt.decode(
                    auth_token,
                    JWT_SERCRET,
                    algorithms=['HS256'],
                    options={'verify_exp': True},
                )
                access_data = jwt_decode(auth_token, verify_exp=verify_exp)
            except ExpiredSignatureError:
                return AccessFailType.EXPIRED
            except Exception:
                return AccessFailType.INVALID
        elif auth_type == AuthType.BASIC.value:
            # Basic认证
            return validate_basic(auth_token)



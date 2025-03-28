#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
from queue import Empty
from time import sleep
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, oauth2
import jwt
from passlib.context import CryptContext
from config import Config
# from temp import SECRET_KEY
from wcferry import Wcf
from model import *
# 用于密码哈希的上下文

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 删除原有的fake_users_db定义
config = Config()
fake_users_db = {}
SECRET_KEY = config.get_config("SECRET_KEY")
# 从配置文件加载用户信息
users_config = config.get_config("users")
if users_config:
    for username, user_info in users_config.items():
        fake_users_db[username] = {
            "username": user_info["username"],
            "hashed_password": pwd_context.hash(user_info["password"]),
            "disabled": user_info.get("disabled", False)
        }
else:
    LOG.error("No users found in config file.")
    exit(1)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return False
    if not pwd_context.verify(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
    user = fake_users_db.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user


logging.basicConfig(level='DEBUG', format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
LOG = logging.getLogger("Demo")

def forward_msg(msg):
    urls = Config().get_config("forward_url")
    payload = json.dumps(msg)
    headers = {
       'User-Agent': 'txb',
       'Content-Type': 'application/json'
    }
    for url in urls:
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            if response:
                return response
        except:
            pass
        sleep(1)

def process_msg(wcf: Wcf):
    """处理接收到的消息"""
    while wcf.is_receiving_msg():
        try:
            msg = wcf.get_msg()
            data = msg.__to_dict__()
            data['is_at'] = msg.is_at(wcf.get_self_wxid())
            response = forward_msg(data)
            if response.status_code == 200:
                LOG.info(msg)
            else:
                LOG.error(f"Forward message error: {response.text}")
        except Empty:
            continue  # Empty message
        except Exception as e:
            LOG.error(f"Receiving message error: {e}")

app = FastAPI()

wcf = Wcf(debug=True)
sleep(5)  # 等微信加载好，以免信息显示异常
LOG.info(f"已经登录: {True if wcf.is_login() else False}")
LOG.info(f"wxid: {wcf.get_self_wxid()}")
wcf.enable_receiving_msg(pyq=True)


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    print(access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
    # return {"access_token": access_token, "token_type": "bearer", "expires_in": access_token_expires}


@app.get('/islogin')
async def is_login(current_user: User = Depends(get_current_user)) -> bool:
    return wcf.is_login()

@app.get('/is_receiving_msg')
async def is_receiving_msg(current_user: User = Depends(get_current_user)) -> bool:
    return wcf.is_receiving_msg()

@app.get('/get_self_wxid')
async def get_self_wxid(current_user: User = Depends(get_current_user)) -> str:
    return wcf.get_self_wxid()

@app.get('/get_msg_types')
async def get_msg_types(current_user: User = Depends(get_current_user)) -> Dict:
    return wcf.get_msg_types()

@app.get('/get_contacts')
async def get_contacts(current_user: User = Depends(get_current_user)) -> List[Dict]:
    return wcf.get_contacts()

@app.get('/get_dbs')
async def get_dbs(current_user: User = Depends(get_current_user)) -> List[str]:
    return wcf.get_dbs()

@app.get('/get_tables/{db}')
async def get_tables(db: str, current_user: User = Depends(get_current_user)) -> List[Dict]:
    return wcf.get_tables(db)

@app.get('/get_user_info')
async def get_user_info(current_user: User = Depends(get_current_user)) -> Dict:
    return wcf.get_user_info()

@app.get('/friends')
async def get_friends(current_user: User = Depends(get_current_user)) -> List[Dict]:
    return wcf.get_friends()

@app.post('/get_audio_msg')
async def get_audio_msg(audio: AudioMsg, current_user: User = Depends(get_current_user)) -> str:
    return wcf.get_audio_msg(audio.id, audio.dir, audio.timeout)

@app.post('/text')
async def send_text(text: TextMessage, current_user: User = Depends(get_current_user))->int:
    """发送文本消息

    Args:
        msg (str): 要发送的消息，换行使用 `\\n\\n` （单杠）；如果 @ 人的话，需要带上跟 `aters` 里数量相同的 @
        receiver (str): 消息接收人，wxid 或者 roomid
        aters (str): 要 @ 的 wxid，多个用逗号分隔；`@所有人` 只需要填写 `all`

    Returns:
        int: 0 为成功，其他失败
    """
    try:
        ats = ''
        if text.aters:            
            if text.aters == "all":
                ats = " @所有人"
                text.aters = "notify@all"
            else:
                wxids = text.aters.split(',')
                for wxid in wxids:
                    ats += f" @{wcf.get_alias_in_chatroom(wxid, text.receiver)}"
        if ats =="":
            msg = text.msg
        else:
            msg = f"{ats}\n\n{text.msg}"    
        status = wcf.send_text(msg, text.receiver, text.aters)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/image')
async def send_image(image: FileMsg, current_user: User = Depends(get_current_user))->int:
    """
    特别提醒：path中不能含有`中文字符`，否则发生不成功
    """
    return wcf.send_image(image.path, image.receiver)

@app.post('/file')
async def send_file(file: FileMsg, current_user: User = Depends(get_current_user))->int:
    """
    特别提醒：path中不能含有`中文字符`，否则发生不成功
    """
    return wcf.send_file(file.path, file.receiver)

@app.post('/rich-text')
async def send_rich_text(rich_text: RichText, current_user: User = Depends(get_current_user))->int:
    return wcf.send_rich_text(rich_text.name, rich_text.account, rich_text.title, rich_text.digest, rich_text.url, rich_text.thumburl, rich_text.receiver)

@app.post('/pat')
async def send_pat_msg(pat: WxidRoom, current_user: User = Depends(get_current_user))->int:
    return wcf.send_pat_msg(pat.roomid, pat.wxid)

@app.post('/forward-msg')
async def forward_wxmsg(msg: ForwardMsg, current_user: User = Depends(get_current_user))->int:
    return wcf.forward_msg(msg.id, msg.receiver)

@app.post('/enable')
async def enable_receiving_msg(pyq: Flag, current_user: User = Depends(get_current_user))->bool:
    """
    flag(pyq): True
    """
    return wcf.enable_receiving_msg()

@app.get('/disable')
async def disable_receiving_msg(current_user: User = Depends(get_current_user))->int:
    return wcf.disable_recv_msg()

@app.post('/sql')
async def query_sql(sql: SqlMsg, current_user: User = Depends(get_current_user))->List[Dict]:
    return wcf.query_sql(sql.db, sql.sql)

@app.post('/receive-transfer')
async def receive_transfer(transfer: TransferMsg, current_user: User = Depends(get_current_user))->int:
    return wcf.receive_transfer(transfer.wxid, transfer.transferid, transfer.transactionid)

@app.get('/pyq/{id}')
async def refresh_pyq(id: int, current_user: User = Depends(get_current_user))->int:
    return wcf.refresh_pyq(id)

@app.post('/save-image')
async def save_image(image: DownloadFile, current_user: User = Depends(get_current_user))->str:
    return wcf.download_image(image.id, image.extra, image.dst, image.timeout)

@app.post('/save-file')
async def download_file(file: DownloadFile, current_user: User = Depends(get_current_user))->str:
    """下载文件
    Args:
        id (int): 消息中 id
        extra (str): 消息中的 extra
        dst (str): 存放文件的路径（目录不存在会出错）,注意直接包含`文件名`！
        timeout (int): 超时时间（秒）

    Returns:
        str: 成功返回存储路径；空字符串为失败，原因见日志。
    """
    return wcf.download_file(file.id, file.extra, file.dst, file.timeout)

@app.get('/revoke-msg/{id}')
async def revoke_msg(id: int, current_user: User = Depends(get_current_user))->int:
    """该方法暂时 未实现"""
    return wcf.revoke_msg(int(id))

@app.post('/add-chatroom-member')
async def add_chatroom_member(chatroom: WxidRoom, current_user: User = Depends(get_current_user))->int:
    return wcf.add_chatroom_members(chatroom.roomid, chatroom.wxid)

@app.post('/delete-chatroom-member')
async def del_chatroom_member(chatroom: WxidRoom, current_user: User = Depends(get_current_user))->int:
    return wcf.del_chatroom_members(chatroom.roomid, chatroom.wxid)

@app.post('/invite-chatroom-member')
async def invite_chatroom_member(chatroom: WxidRoom)->int:
    return wcf.invite_chatroom_members(chatroom.roomid, chatroom.wxid)

@app.get('/query-chatroom-member/{roomid}')
async def query_chatroom_member(roomid: str, current_user: User = Depends(get_current_user))->Dict:
    return wcf.get_chatroom_members(roomid)

@app.post('/alias')
async def get_alias(user: WxidRoom, current_user: User = Depends(get_current_user))->str:
    return wcf.get_alias_in_chatroom(user.wxid, user.roomid)

# @app.post('/delete-file')
# async def delete_file(path: str, token: str) ->str:
#     if token == Config().get_config('delete_token'):
#         try:
#             os.remove(path)
#             return path
#         except FileNotFoundError:
#             return f'{path}文件未找到'
#         except PermissionError:
#             return f'{path}没有权限删除文件,请手动删除'
#         except Exception as e:
#             return f'删除{path}出错，{e}'




if __name__ == "__main__":
    import threading
    threading.Thread(target=wcf.keep_running, daemon=True).start()  # 启动保持运行的线程
    threading.Thread(target=process_msg, name="GetMessage", args=(wcf,), daemon=True).start()  # 启动消息处理线程
    uvicorn.run(app, host="0.0.0.0", port=10010)  # 启动 FastAPI 服务器
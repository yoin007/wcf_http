from pydantic import BaseModel
from typing import Optional

class TextMessage(BaseModel):
    msg: str
    receiver: str
    aters: Optional[str] = ""  # 提供默认值，如果请求中没有提供 aters，则使用空字符串

class AudioMsg(BaseModel):
    id: int
    dir: str
    timeout: Optional[int] = 3

class FileMsg(BaseModel):
    path: str
    receiver: str

class DownloadFile(BaseModel):
    id: int
    extra: str
    dst: str
    timeout: Optional[int] = 30

class RichText(BaseModel):
    name: str
    account: str
    title: str
    digest: str
    url: str
    thumburl: str
    receiver: str

class XmlMsg(BaseModel):
    receiver: str
    xml: str
    type: int
    path: Optional[str] = None

class WxidRoom(BaseModel):
    roomid: str
    wxid: str

class Wxid(BaseModel):
    wxid: str

class Friend(BaseModel):
    v3: str
    v4: str
    scene: Optional[int] = 30

class ForwardMsg(BaseModel):
    id: int
    receiver: str

class Flag(BaseModel):
    flag: bool

class SqlMsg(BaseModel):
    db: str
    sql: str

class TransferMsg(BaseModel):
    wxid: str
    transferid: str
    transactionid: str
    

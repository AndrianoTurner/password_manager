import sqlite3
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_password(master_password,password)->bytes:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(key)
    token = f.encrypt(password)
    return token
def decrypt_password(master_password,password)->bytes:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(key)
    return f.decrypt(password)



def singleton(class_):
    instances = {}

    def get_instance(*args,**kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args,**kwargs)
        return instances[class_]
    return get_instance

@singleton
class Database():
    def __init__(self):
        self.db : sqlite3.Connection = sqlite3.connect("manager.db")
        self.cursor : sqlite3.Cursor = self.db.cursor()
        self.__first_init__()
    def __first_init__(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, site TEXT, login TEXT, password BLOB)""")
        self.db.commit()
    def add_record(self,master_pass,site : str,login: str,password : str):
        password = encrypt_password(master_pass)
        self.cursor.execute("INSERT INTO passwords(site,login,password) VALUES(?,?,?)",(site,login,password))
        self.db.commit()
    def delete_record(self,record_id : int):
        self.cursor.execute("DELETE FROM passwords WHERE id = ?",(record_id,))
        self.db.commit()
    def get_record(self,record_id : int):
        record = self.cursor.execute("SELECT site,login,password FROM passwords where id = ?",(record_id,)).fetchone()
        return record
    def update_record(self,master_pass,record_id : int, site=None,login=None,password=None,**kwargs):
        p_site,p_login,p_password = self.get_record(record_id)
        self.cursor.execute("UPDATE passwords SET site = ?,login = ?,password = ? WHERE id = ?",(site,login,password,record_id))
        self.db.commit()
    def close(self):
        self.cursor.close()
        self.db.close()
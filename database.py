import sqlite3
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(master_password,salt=None) -> (str,Fernet):
    master_password = master_password.encode()
    if salt: salt = base64.b64decode(salt)
    else: salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    return salt,Fernet(key)

def encrypt_data(master_password : str,password : str)->bytes:
    salt,f = generate_key(master_password)
    password = password.encode()
    token = f.encrypt(password)
    salt = base64.b64encode(salt)
    return salt,token

def decrypt_data(master_password,password,salt)->bytes:
    salt,f = generate_key(master_password,salt)
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
            CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, site TEXT, login TEXT, password BLOB, salt BLOB)""")
        self.db.commit()
    def add_record(self,master_pass,site : str,login: str,password : str):
        salt,password = encrypt_data(master_pass,password)
        self.cursor.execute("INSERT INTO passwords(site,login,password,salt) VALUES(?,?,?,?)",(site,login,password,salt))
        self.db.commit()
    def delete_record(self,record_id : int):
        self.cursor.execute("DELETE FROM passwords WHERE id = ?",(record_id,))
        self.db.commit()
    def get_record(self,record_id : int):
        record = self.cursor.execute("SELECT site,login,password,salt FROM passwords where id = ?",(record_id,)).fetchone()
        return record
    def get_password(self,site : str,master_password : str) -> str:
        salt,password = self.cursor.execute("SELECT salt,password FROM passwords WHERE site = ?",(site,)).fetchone()
        password = decrypt_data(master_password,password,salt)
        return password


    def update_record(self,master_pass,record_id : int, site=None,login=None,password=None,**kwargs):
        p_site,p_login,p_password = self.get_record(record_id)
        self.cursor.execute("UPDATE passwords SET site = ?,login = ?,password = ? WHERE id = ?",(site,login,password,record_id))
        self.db.commit()
    def close(self):
        self.cursor.close()
        self.db.close()



from database import Database
from database import encrypt_data,decrypt_data
import base64
if __name__ == '__main__':
    db = Database()
    db.add_record("1234","test","aboba","12345678")
    p = db.get_password("test","1234")
    print(p)


from database import Database
from database import encrypt_data,decrypt_data
import base64
from tkinter import *

class PasswordManager():
    def __init__(self) -> None:
        self.db = Database()
        self.gui = Tk()
        self.gui.title = "Password Manager"
        self.gui.geometry("1200x720")
        self.text_input = Entry()
        self.decrypt_btn = Button(text="Decrypt")
        self.text_input.pack()
        self.decrypt_btn.pack()
        self.decrypt_btn.bind("<ButtonPress-1>",self.__decrypt_click)
        self.gui.mainloop()

    def __decrypt_click(self,event):
        self.password = self.text_input.get()
        print(self.password)

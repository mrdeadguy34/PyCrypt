"""imports"""
from tkinter.filedialog import askopenfilename, askdirectory
from tkinter import messagebox
from tkinter import *
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from PIL import Image, ImageTk
import sys
import os
"""class"""
class Window(Frame):
    def __init__(self,master=None):
        Frame.__init__(self, master)
        self.master = master
        self.BaseWindow()

    def RSAGenerate(self):
        try:
            os.chdir(self.Dir)
        except:
            pass
        SaveName = self.NameEntry.get()
        Phrase = self.PassEntry.get()
        key = RSA.generate(2048)
        self.RSAMenu.destroy()
        try:
            encKey = key.exportKey(passphrase=Phrase,pkcs=8,protection="scryptAndAES128-CBC")
        except ValueError:
            messagebox.showinfo("Empty Passphrase","Please enter a passphrase:")
            sys.exit()
        with open(SaveName,"wb") as F:
            F.write(encKey)
        with open(SaveName,"rb") as F:
            encodedKey = F.read()
            key = RSA.import_key(encodedKey,passphrase=Phrase)
            with open(SaveName+".pem","wb") as L:
                L.write(key.publickey().exportKey())
        sys.exit()

    def DirectorySelect(self):
        self.Dir = askdirectory()

    def CreateRSA(self):
        root.withdraw()
        self.RSAMenu = Toplevel()
        self.RSAMenu.iconbitmap("logo.ico")
        self.RSAMenu.geometry("340x180")
        self.app = (self.RSAMenu)
        PassLabel = Label(self.RSAMenu,text="Passphrase:")
        PassLabel.pack()
        self.PassEntry = Entry(self.RSAMenu)
        self.PassEntry.pack()
        DirButton = Button(self.RSAMenu,text="Choose directory",command=self.DirectorySelect)
        DirButton.pack()
        NameLabel = Label(self.RSAMenu,text="Save name:")
        NameLabel.pack()
        self.NameEntry = Entry(self.RSAMenu)
        self.NameEntry.pack()
        CreateButton = Button(self.RSAMenu,text="Create",command=self.RSAGenerate)
        CreateButton.pack()

    def EncryptFile(self):
        self.RSAKey = askopenfilename()
        if self.RSAKey == False:
            sys.exit()
        else:
            pass

        EncFile = open(self.File+".bin","wb")
        try:
            Key = RSA.import_key(open(self.RSAKey).read())
        except ValueError:
            messagebox.showinfo("Invalid Key","Invalid key; Possibly private.")
            sys.exit()
        session_key = get_random_bytes(16)
        ciphered = PKCS1_OAEP.new(Key)
        EncFile.write(ciphered.encrypt(session_key))
        cipher_AES = AES.new(session_key,AES.MODE_EAX)
        ciphertext, tag = cipher_AES.encrypt_and_digest(open(self.File,"rb").read())
        [ EncFile.write(x) for x in (cipher_AES.nonce, tag, ciphertext) ]
        sys.exit()

    def EncryptRSA(self):
        self.EncryptMenu.destroy()
        self.File = askopenfilename()
        if self.File == False:
            sys.exit()
        else:
            pass
        self.EncryptRSAMenu = Toplevel()
        self.EncryptRSAMenu.iconbitmap("logo.ico")
        self.EncryptRSAMenu.geometry("150x150")
        self.app = (self.EncryptRSAMenu)
        RSAButton = Button(self.EncryptRSAMenu,text="Choose RSA",command=self.EncryptFile)
        RSAButton.pack(fill=BOTH,expand=1)

    def Encrypter(self):
        root.withdraw()
        self.EncryptMenu = Toplevel()
        self.EncryptMenu.iconbitmap("logo.ico")
        self.EncryptMenu.geometry("150x150")
        self.app = (self.EncryptMenu)
        File = Button(self.EncryptMenu,text="Choose file",command=self.EncryptRSA)
        File.pack(fill=BOTH,expand=1)

    def DecryptFile(self):
        self.PrivateKey = askopenfilename()
        Phrase = self.PassEntry.get()
        self.DecryptRSAMenu.destroy()
        if self.PrivateKey == False:
            sys.exit()
        else:
            pass
        KeyFile = open(self.PrivateKey,'rb')
        try:
            PrivateKey = RSA.import_key(KeyFile.read(),passphrase=Phrase)
        except ValueError:
            messagebox.showinfo("Invalid Key/Phrase:","That RSA Key or phrase is not valid!")
            sys.exit()
        KeyFile.close()
        with open(self.File,"rb") as File:
            enc_session_key, nonce, tag, ciphertext = \
               [ File.read(x) for x in (PrivateKey.size_in_bytes(), 16, 16, -1) ]
            cipher_rsa = PKCS1_OAEP.new(PrivateKey)
            session_key = cipher_rsa.decrypt(enc_session_key)
            cipher_aes = AES.new(session_key,AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open(self.File+".dec","wb") as F:
            F.write(data)
        sys.exit()

    def DecryptRSA(self):
        self.DecryptMenu.destroy()
        self.File = askopenfilename()
        if self.File == False:
            sys.exit()
        else:
            pass
        self.DecryptRSAMenu = Toplevel()
        self.DecryptRSAMenu.iconbitmap("logo.ico")
        self.DecryptRSAMenu.geometry("150x100")
        self.app = (self.DecryptRSAMenu)
        PassLabel = Label(self.DecryptRSAMenu,text="Passphrase:")
        PassLabel.pack()
        self.PassEntry = Entry(self.DecryptRSAMenu)
        self.PassEntry.pack()
        RSAButton = Button(self.DecryptRSAMenu,text="Choose RSA",command=self.DecryptFile)
        RSAButton.pack()



    def Decrypter(self):
        root.withdraw()
        self.DecryptMenu = Toplevel()
        self.DecryptMenu.iconbitmap("logo.ico")
        self.DecryptMenu.geometry("150x150")
        self.app = (self.DecryptMenu)
        File = Button(self.DecryptMenu,text="Choose file",command=self.DecryptRSA)
        File.pack(fill=BOTH,expand=1)

    def CreatePublic(self):
        PrivateKeyDir = askopenfilename()
        Phrase = self.PassEntry.get()
        try:
            PrivKey = open(PrivateKeyDir,'rb')
        except:
            messagebox.showinfo("Invalid file","That key could not be found.")
            sys.exit()
        try:
            Key = RSA.import_key(PrivKey.read(),passphrase=Phrase)
        except ValueError:
            messagebox.showinfo("Invalid Key/Phrase:","That RSA Key or phrase is not valid!")
            sys.exit()
        with open(PrivateKeyDir+".pem","wb") as F:
            F.write(Key.publickey().exportKey())
        sys.exit()

    def PublicKeyMenu(self):
        root.withdraw()
        self.PublicMenu = Toplevel()
        self.PublicMenu.iconbitmap("logo.ico")
        self.PublicMenu.geometry("150x100")
        self.app = (self.PublicMenu)
        PassLabel = Label(self.PublicMenu,text="Passphrase:")
        PassLabel.pack()
        self.PassEntry = Entry(self.PublicMenu)
        self.PassEntry.pack()
        ChoosePriv = Button(self.PublicMenu,text="Choose private key",command=self.CreatePublic)
        ChoosePriv.pack()

    def BaseWindow(self):
        self.master.title("PyCrypt")
        self.pack(fill=BOTH,expand=1)
        self.Image = Image.open("logoSmall.png")
        self.ImageLab = ImageTk.PhotoImage(self.Image)
        LogoLabel = Label(self)
        LogoLabel.config(image=self.ImageLab)
        LogoLabel.pack(fill=BOTH,expand=1)
        TitleLabel = Label(self,text="Welcome to PyCrypt:")
        TitleLabel.pack(fill=BOTH,expand=1)
        CreateKeyButton = Button(self,text="Create RSA Keys",command=self.CreateRSA)
        CreateKeyButton.pack(fill=BOTH,expand=1)
        CreatePublicButton = Button(self,text="Create Public Key",command=self.PublicKeyMenu)
        CreatePublicButton.pack(fill=BOTH,expand=1)
        EncryptDataButton = Button(self,text="Encrypt File",command=self.Encrypter)
        EncryptDataButton.pack(fill=BOTH,expand=1)
        DecryptDataButton = Button(self,text="Decrypt File",command=self.Decrypter)
        DecryptDataButton.pack(fill=BOTH,expand=1)
        




"""main"""
if __name__ == "__main__":
    root = Tk()
    root.iconbitmap("logo.ico")
    root.geometry("600x400")
    app = Window(root)
    root.mainloop()


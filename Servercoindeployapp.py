from ast import If
from audioop import error
from http import server
from telnetlib import SE
import ipaddress
import tkinter as tk
import hashlib
import math
import time
from wsgiref.simple_server import server_version
Variablelevel = 1
max_drive = ""
def fixserverset(servers):
      listthing = {}
      newvalue = 0
      print("servers: "+str(servers))
      for item in servers:
          listthing[newvalue]=str(servers[item])
          newvalue+=1
      return listthing
class Procedures:
    def __init__(self):
        self.serverips = []

    def getthatblockaccepted(self, blockdata):
        lola = {"Blockstuff": blockdata, "Obtainmentdate": time.time()}
        return lola
def is_valid_ip(ip_str):
    try:
        # Convert string to IP address
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False
def delete_fifth_character(input_string,startnum):
   newstring = ''
   numswenthrough = 0
   for item in input_string:
       numswenthrough+=1
       if not startnum == numswenthrough:
           newstring+=item
   return newstring
from unittest.util import _MAX_LENGTH
import requests
from bs4 import BeautifulSoup
import hashlib
import flask
from flask import Flask,request,jsonify

import time
import json
import ecdsa
from hashlib import new, sha256
from threading import Thread
numberoftries = 0
with open("numberoftries.txt","w") as file:
       file.write(str(numberoftries))
import os
import psutil
import math
import socket
import pickle
import sys
import math
from flask import request,jsonify,send_file
def export_sqlite_database(database_path, output_file):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    with open(output_file, 'w') as file:
        for line in conn.iterdump():
            file.write('%s\n' % line)

    conn.close()
def import_sql_file(sql_file_path, new_database_path):
    # Connect to the new SQLite database
    conn = sqlite3.connect(new_database_path)
    cursor = conn.cursor()

    # Read the SQL commands from the file
    with open(sql_file_path, 'r') as file:
        sql_commands = file.read()

    # Split the SQL commands into individual statements
    commands = sql_commands.split(';')

    # Execute each SQL command
    for command in commands:
        try:
            cursor.execute(command)
        except sqlite3.Error as e:
            print(f"Error executing command: {e}")

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

import sqlite3
import threading
import subprocess

import copy
import sqlite3
import re

def remove_sql(input_string):
    # Regular expression pattern to match SQL keywords and common SQL syntax
    sql_pattern = r'\b(SELECT|UPDATE|INSERT|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b|\-\-|;'

    # Remove SQL code using regex
    cleaned_string = input_string.replace("SELECT","SEPECT")
    cleaned_string = input_string.replace("UPDATE","UPDETE")
    cleaned_string = input_string.replace("INSERT","InPERT")
    cleaned_string = input_string.replace("DROP","DRIP")
    cleaned_string = input_string.replace("CREATE","CREETE")
    cleaned_string = input_string.replace("ALTER","ALTAR")
    cleaned_string = input_string.replace("TRUNCATE","TRONCATE")

    return cleaned_string


def convertthething(verifyingkey):
        verifyingkeyloader = str(verifyingkey)
        stufflist = ''
        for i in range(len(verifyingkeyloader)-59):
                   stufflist = stufflist+verifyingkeyloader[i+30]
        
        thingpower = ''
        Devicet = stufflist
       
        Num1 = 0
        Num2 = 0
        wentthroughnum = -1
        Devicex = ""
        devicey = ""
               
        neothing = {}
        for item in stuffindata:
               if not item == '/':
                  neothing[1] = str(item)
               
               
        for item in Devicet:
                wentthroughnum+=1
                if item == neothing[1] and Num1==0:
                 Num1 = wentthroughnum
                 
                if wentthroughnum == Num1+1 and item == 'n' and Num1>0:
                 Num2 = wentthroughnum
        
        Devicet = Devicet.replace(neothing[1],'')
        Devicet = delete_fifth_character(Devicet,Num2)
        thingpower33 = '''-----BEGIN PUBLIC KEY-----
REPLACE
-----END PUBLIC KEY-----'''
        wentthroughnum2 = -1
        for item in Devicet:
           if wentthroughnum2<Num1-1:
                 wentthroughnum2+=1
    
                 Devicex = Devicex+item
    
           else:
                 break
               
              
        print(Devicex)
        wentthroughnum3 = -1
        for item in Devicet:
         wentthroughnum3+=1
         if wentthroughnum3>=Num1:
               devicey+=item
               thingpower = Devicex+'\n'+devicey
               
               
               thingpower33 = thingpower33.replace('REPLACE',thingpower)
        thingpower33 = '-----BEGIN PUBLIC KEY-----\n'+str(thingpower)+'\n-----END PUBLIC KEY-----'
        return thingpower33
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import time
import pickle
import hashlib
import math
import socket
import requests
import base64
import copy
import random
import requests
from flask import app
from flask import request
from flask import Flask,jsonify
thingpower33 = '''-----BEGIN PUBLIC KEY-----
REPLACE
-----END PUBLIC KEY-----'''
stuffindata = ''
with open('TextFile1.txt','r') as file:
    stuffindata = file.read()
def get_local_ip():
    # Get the local IP address of the computer
  if SpecialDevice == 2:
    return socket.gethostbyname(socket.gethostname())  
  else:
    return SpecialDomain
def get_local_ip2():
    # Get the local IP address of the computer
    return socket.gethostbyname(socket.gethostname())  
 
selfnum=1
listofkeyeys = {}
VMDATALIST = {}
VMDATALIST2 = {}
timewaitthing = 1800
timethingthing = False
thepowerthing = False
import mnemonic
from mnemonic import Mnemonic

letterdict = {}
SERVERDATALIST = {}
letterstring = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
def fourthround(num):
  if num%0.25>0.125:
    num =math.floor(num*4)/4
    num+=0.25
    return num
  else:
   return math.floor(num*4)/4
max600thingnum = 6
def ConvertTheNumber(Number):
    if Number<0 and Number>=-3:
        NewNumber = int(Number)
        Number = 3+NewNumber
        return Number
    elif Number<0:
        NewNumber = int(Number)
        Number = max600thingnum+NewNumber
        
        return Number
    else:
        return Number
def get_ram_info():
    virtual_memory = psutil.virtual_memory()
    swap_memory = psutil.swap_memory()
    virmemav = virtual_memory.available
    return virmemav
def set_vm_memory(vm_name, new_ram_size):

    command = f'VBoxManage modifyvm {vm_name} --memory {new_ram_size}'

    try:
        subprocess.run(command, check=True, shell=True)
        print(f"RAM size for {vm_name} updated to {new_ram_size} MB.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return False
def modify_vm_storage(vm_name, new_size_gb):
    try:
        # Build the VBoxManage command to modify storage
        command = [
            'VBoxManage',
            'modifyhd',
            vm_name + '.vdi',  # Specify the path to your VM's virtual disk file
            '--resize', str(new_size_gb)  # Set the new size in gigabytes
        ]

        # Run the command using subprocess
        subprocess.run(command, check=True)
        
        print(f"Storage for VM '{vm_name}' modified successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error modifying storage for VM '{vm_name}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def on_focus_in(event):
    if text_box.get("1.0", tk.END).strip() == PlaceHolderText:
        text_box.delete("1.0", tk.END)  # Remove the placeholder text
        text_box.config(fg='black')     # Set normal text color

def on_focus_out(event):
    if text_box.get("1.0", tk.END).strip() == "":
        text_box.insert("1.0", PlaceHolderText)  # Put the placeholder back
        text_box.config(fg='grey')               # Set placeholder text color

def on_key_press(event):
    if text_box.get("1.0", tk.END).strip() == PlaceHolderText:  # If placeholder is present
        text_box.delete("1.0", tk.END)  # Remove the placeholder text
        text_box.config(fg='black')     # Set normal text color
sigthinglisty = {}
# Replace this with your seed phrase
httpthingy = ""
SpecialDevice = 0
SpecialDomain = ""

SPECIALPORT = 0
DATATRANSFERPOWER = 0
seed_phrase = ""
TABLEOFWEBSITESTOCHECK = []
inthing = ""
inthinghash = ""
loadthisloop = True
allowedtostartpowerserver = False

PriceperGBperday = 0.0


PriceperGBbutFIAT = 0.0
RAMPRICEPERGB = 0.0

RAMPRICEPERGBFIAT = 0.0
DATATRANSFERPRICEPERGB = 0.0

DATATRANSFERPRICEPERGBFIAT = 0.0
VCPUPRICE = 0.0
commands = {}
files = {}

abspathvariable = os.path.join(max_drive, "Wallets")

def addcommands(command,vm):
    if not vm in commands:
        commands[vm] = {"Commands":{},"Count":1}
        commands[vm]["Commands"][int(commands[vm]["Count"])] = {"Command":command,"Used":False}
    commands[vm]["Count"]+=1
def addfiles(file,vm):
    if not vm in files:
        files[vm] = {"Files":{},"Count":1}
        files[vm]["Files"][int(files[vm]["Count"])] = {"File":file,"Used":False}
    files[vm]["Count"]+=1
def labelfileasused(count,vm):
    files[vm]["Files"][count]["Used"] = True
def labelcommandasused(count,vm):
    files[vm]["Commands"][count]["Used"] = True

def copy_vmname_to_guest(vm_name, guest_user, guest_pass):
    temp_filename = f"{vm_name}.txt"
    abs_path = os.path.abspath(temp_filename)

    with open(abs_path, "w") as f:
        f.write(vm_name)
        f.flush()
        os.fsync(f.fileno())

    print(f"Temp file created at: {abs_path}")

    try:
        print(f"?? Copying VM name into {vm_name}...")

        subprocess.run([
            'VBoxManage', 'guestcontrol', vm_name,
            'copyto',
            '--username', guest_user,
            '--password', guest_pass,
            abs_path,
            f"/home/{guest_user}/vmname.txt"
        ], check=True)

        print(f"? Copied to /home/{guest_user}/vmname.txt successfully")

    except subprocess.CalledProcessError as e:
        print(f"? Failed on VM {vm_name}: {e}")

    finally:
        os.remove(abs_path)


VCPUPRICEFIAT = 0.0
VMLOADDRIVE = ""
ISOFILE = ""
SELFVMTHINGLOADERIP = ""

PlaceHolderText = "What http protocol does your server use?"
loadinputty = 0
Variablelevel = 1
Variable1 = ""
Variable2 = ""
Variable3 = ""
Variable4 = ""
Variable5 = ""
guestuser = ""
guestpass = ""
passedthrough = False
def automaticfix():
    passedthrough = True 
    return "Did it"
def automaticfixpart2():
    if passedthrough == True:
        return True
def submit_text():
    global Variablelevel,httpthingy,SpecialDevice,SpecialDomain,inthing,inthinghash,loadthisloop,loadinputty,VMLOADDRIVE,ISOFILE,SELFVMTHINGLOADERIP,TABLEOFWEBSITESTOCHECK,PriceperGBperday,PriceperGBbutFIAT,RAMPRICEPERGB,RAMPRICEPERGBFIAT,DATATRANSFERPRICEPERGB,DATATRANSFERPRICEPERGBFIAT,VCPUPRICE,VCPUPRICEFIAT,allowedtostartpowerserver,DATATRANSFERPOWER,SPECIALPORT,seed_phrase, Variable1, Variable2, Variable3, Variable4, Variable5, PlaceHolderText,guestuser,guestpass

    user_text = text_box.get("1.0", tk.END).strip()
    if user_text == PlaceHolderText or user_text == "":  # Check if the user input is valid
        print("No valid input submitted.")
    else:
        print(f"User entered: {user_text}")
        
        # Assign user input to the corresponding variable
        if Variablelevel == 1:
            httpthingy = user_text
            with open("httpthingy.txt","w") as file:
                file.write(httpthingy)
            PlaceHolderText = "1. for special domain and 2 for not."
            Variablelevel += 1

        elif Variablelevel == 2:
           if not SpecialDevice>0:
            SpecialDevice = int(user_text)
            with open("SpecialDevice.txt","w") as file:
                 file.write(str(SpecialDevice))
            if SpecialDevice == 1:
             PlaceHolderText = "What is the special domain?"
            else:
             PlaceHolderText = "What is the port of this thing?"
             Variablelevel+=1

           else:
            if SpecialDevice == 1:
             SpecialDomain = user_text
             with open("SpecialDomain.txt","w") as file:
                 file.write(str(SpecialDomain))
             PlaceHolderText = "What is the port of this thing?"
             Variablelevel+=1
            else:
             PlaceHolderText = "What is the port of this thing?"
             Variablelevel+=1
             print("There is no special domain it seems...")
        elif Variablelevel == 3:
            SPECIALPORT = int(user_text)
            with open("SPECIALPORT.txt","w") as file:
                 file.write(str(SPECIALPORT))
            PlaceHolderText = "What is the total amount of data transfer megabytes that are usable on this machine?"
            Variablelevel+=1
        elif Variablelevel == 4:
            DATATRANSFERPOWER = int(user_text)
            with open("DATATRANSFERPOWER.txt","w") as file:
                 file.write(str(DATATRANSFERPOWER))
            PlaceHolderText = "Seed phrase"
            Variablelevel+=1

        elif Variablelevel == 5:
            
            seed_phrase = user_text
            with open("seedphrase.txt","w") as file:
                 file.write(str(seed_phrase))
            PlaceHolderText = "What is the genesis password?"
            Variablelevel+=1
            
        elif Variablelevel == 6:
            inthing = user_text
            inthinghash = str(hashlib.sha256(inthing.encode('utf8')).hexdigest())
            with open("inthinghash.txt","w") as file:
                 file.write(str(inthing))
            if inthinghash == "f7af4d9ee489c849ac840db125ed35f76fcae913f5e645e98067efcb14202bbc":
             allowedtostartpowerserver = True
          
            PlaceHolderText = "1. for stopping this and 2. for continuing this"
            Variablelevel+=1
        elif Variablelevel == 7:
            if loadinputty<=0:
             loadinputty = int(user_text)
             
             if loadinputty == 2:
              PlaceHolderText = "What is the Address of the website you are getting your data from?"
             else:
              PlaceHolderText = "What is the amount of server coins you want the user to spend per gigabyte."
              Variablelevel+=1
            else:
             if loadinputty == 2:
             
              newserver = user_text
              loadinputty = 0
              PlaceHolderText = "1. for stopping this and 2. for continuing this"
              TABLEOFWEBSITESTOCHECK.append(newserver)
              with open("Tableofwebsitestocheck.txt","w") as file:
                  file.write(str(TABLEOFWEBSITESTOCHECK))
             else:
              
              print("loadinputty: "+str(loadinputty))
              Variablelevel+=1
              PlaceHolderText = "What is the amount of server coins you want the user to spend per gigabyte."
        elif Variablelevel == 8:
            PriceperGBperday = float(user_text)
            with open("PriceperGBperday.txt","w") as file:
                  file.write(str(PriceperGBperday))
            PlaceHolderText = "What is the FIAT price of this thing? If there isn't one just type NONE."
            Variablelevel+=1
            
        elif Variablelevel == 9:
            if not user_text == "NONE":
             PriceperGBbutFIAT = float(user_text)
             with open("PriceperGBbutFIAT.txt","w") as file:
                  file.write(str(PriceperGBbutFIAT))
            else:
             PriceperGBbutFIAT = user_text
            PlaceHolderText = "What is the price of RAM per Gigabyte per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 10:
            RAMPRICEPERGB = float(user_text)
            with open("RAMPRICEPERGB.txt","w") as file:
                  file.write(str(RAMPRICEPERGB))
            PlaceHolderText = "What is the price of RAM per gigabyte per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 11:
            RAMPRICEPERGBFIAT = float(user_text)
            with open("RAMPRICEPERGBFIAT.txt","w") as file:
                  file.write(str(RAMPRICEPERGBFIAT))
            PlaceHolderText = "What is the price of DATA TRANSFER per Gigabyte per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 12:
            DATATRANSFERPRICEPERGBFIAT = float(user_text)
            with open("DATATRANSFERPRICEPERGBFIAT.txt","w") as file:
                  file.write(str(DATATRANSFERPRICEPERGBFIAT))
            PlaceHolderText = "What is the price of DATA TRANSFER per gigabyte per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 13:
            DATATRANSFERPRICEPERGB = float(user_text)
            with open("DATATRANSFERPRICEPERGB.txt","w") as file:
                  file.write(str(DATATRANSFERPRICEPERGB))
            PlaceHolderText = "What is the price of 1 VCPU per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 14:
            VCPUPRICE = float(user_text)
            with open("VCPUPRICE.txt","w") as file:
                  file.write(str(VCPUPRICE))
            PlaceHolderText = "What is the price of 1 VCPU per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 15:
            VCPUPRICEFIAT = float(user_text)
            with open("VCPUPRICEFIAT.txt","w") as file:
                  file.write(str(VCPUPRICEFIAT))
            PlaceHolderText = "What is the name of the drive that the VMs are stored in?"
            Variablelevel+=1
        elif Variablelevel == 16:
            VMLOADDRIVE = user_text
            with open("VMLOADDRIVE.txt","w") as file:
                  file.write(str(VMLOADDRIVE))
            PlaceHolderText = "What is the address of the ISO file?"
            Variablelevel+=1
            
        elif Variablelevel == 17:
            ISOFILE = user_text
            with open("ISOFILE.txt","w") as file:
                  file.write(str(ISOFILE))
            PlaceHolderText = "What is the IP address of the VM you use for the thing that allows the VMs this makes to get their IP?"
            Variablelevel+=1
        elif Variablelevel == 18:
            if PlaceHolderText == "The thing has finished. How'd you get here?":
                print("JUST QUIT NOW!")
                root.quit()
                print("YOU WERE SUPPOSED TO QUIT!")
            SELFVMTHINGLOADERIP = user_text
            with open("SELFVMTHINGLOADERIP.txt","w") as file:
                  file.write(str(SELFVMTHINGLOADERIP))
            PlaceHolderText = "What is the guest user of the VMs"
            Variablelevel+=1
        elif Variablelevel == 19:
            if PlaceHolderText == "The thing has finished. How'd you get here?":
                print("JUST QUIT NOW!")
                root.quit()
                print("YOU WERE SUPPOSED TO QUIT!")
            guestuser = user_text
            with open("guestuser.txt","w") as file:
                  file.write(str(guestuser))
            PlaceHolderText = "What is the guest pass of the VMS"
            Variablelevel+=1
        elif Variablelevel == 20:
            if PlaceHolderText == "The thing has finished. How'd you get here?":
                print("JUST QUIT NOW!")
                root.quit()
                print("YOU WERE SUPPOSED TO QUIT!")
            guestpass = user_text
            with open("guestpass.txt","w") as file:
                  file.write(str(guestpass))
            PlaceHolderText = "The thing has finished. How'd you get here?"
            root.quit()  # Exit the application after the fifth submission
            root.destroy()
            print("YOU SHOULD'VE CLOSED THE TKINTER!")
        # Increment the level

        # Clear the text box and reset it with new placeholder text
        text_box.delete("1.0", tk.END)
        text_box.insert("1.0", PlaceHolderText)
        text_box.config(fg='grey')

# Create the main window
allowedtostartpowerserver = automaticfixpart2()
if allowedtostartpowerserver == True:
    with open("Powerserver3.txt","w") as file:
        file.write("SO WHAT???")

root = tk.Tk()
root.title("Servercoin GUI part 1.")

# Make the window full screen
root.attributes('-fullscreen', True)

# Style the Textbox (make it more modern-looking)
text_box = tk.Text(root, height=10, fg='grey', bg='#f0f0f0', padx=10, pady=10, bd=2, relief="solid", font=("Arial", 18))
text_box.insert("1.0", PlaceHolderText)  # Insert the initial placeholder text
text_box.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)  # Fill the entire available space

# Bind focus in/out events to manage the placeholder
text_box.bind("<FocusIn>", on_focus_in)
text_box.bind("<FocusOut>", on_focus_out)

# Bind key press event to remove placeholder when typing starts
text_box.bind("<Key>", on_key_press)

# Style the Submit Button (bigger and light green, long width)
submit_button = tk.Button(root, text="Submit", command=submit_text, bg='lightgreen', font=("Arial", 18, "bold"), padx=50, pady=20)
submit_button.pack(pady=20, fill=tk.X)  # Fill the width of the screen

# Start the Tkinter event loop
root.mainloop()

# After exiting the loop, we can print the collected variables if needed
print("Final Variables:")


print(httpthingy) 
print(SpecialDevice)
print(SpecialDomain)
print(TABLEOFWEBSITESTOCHECK)
PriceperGB = PriceperGBperday
PriceperGBperday = PriceperGBperday*(10**8)
PriceperGB = PriceperGBperday
RAMPRICEPERGB = RAMPRICEPERGB*(10**8)
RAMPRICEPERGB = math.floor(RAMPRICEPERGB)
DATATRANSFERPRICEPERGB=DATATRANSFERPRICEPERGB*(10**8)
DATATRANSFERPRICEPERGB=math.floor(DATATRANSFERPRICEPERGB)
VCPUPRICE = VCPUPRICE*(10**8)
VCPUPRICE = math.floor(VCPUPRICE)
Variablelevel2 = 1
IP = ""
Port = 0
Type = 0
with open("inthinghash.txt","r") as file:
    inthing = str(file.read())
    inthinghash = str(hashlib.sha256(inthing.encode('utf8')).hexdigest())
    if inthinghash == "f7af4d9ee489c849ac840db125ed35f76fcae913f5e645e98067efcb14202bbc":
             allowedtostartpowerserver = True
    else:
     with open("Okthatswhy.txt","w") as file:
         file.write("Right here!: "+str(inthinghash))
with open("allowedtostartpowerserver.txt","w") as file:
    file.write(str(allowedtostartpowerserver))

try: 
 with open('httpthingy.txt','r') as file:
  httpthingy = str(file.read())
except: 
  print('failed')
try: 
 with open('Variablelevel.txt','r') as file:
  Variablelevel = str(file.read())
except: 
  print('failed')
try: 
 with open('httpthingy.txt','r') as file:
  httpthingy = str(file.read())
except: 
  print('failed')
try: 
 with open('SpecialDevice.txt','r') as file:
  SpecialDevice = int(file.read())
except: 
  print('failed')
try: 
 with open('SpecialDomain.txt','r') as file:
  SpecialDomain = int(file.read())
except: 
  print('failed')
try: 
 with open('inthing.txt','r') as file:
  inthing = str(file.read())
except: 
  print('failed')
try: 
 with open('loadthisloop.txt','r') as file:
  loadthisloop = str(file.read())
except: 
  print('failed')
try: 
 with open('loadinputty.txt','r') as file:
  loadinputty = str(file.read())
except: 
  print('failed')
try: 
 with open('VMLOADDRIVE.txt','r') as file:
  VMLOADDRIVE = str(file.read())
except: 
  print('failed')
try: 
 with open('ISOFILE.txt','r') as file:
  ISOFILE = str(file.read())
except: 
  print('failed')
try: 
 with open('SELFVMTHINGLOADERIP.txt','r') as file:
  SELFVMTHINGLOADERIP = str(file.read())
except: 
  print('failed')
try: 
 with open('TABLEOFWEBSITESTOCHECK.txt','r') as file:
  TABLEOFWEBSITESTOCHECK = str(file.read())
except: 
  print('failed')
try: 
 with open('PriceperGBperday.txt','r') as file:
  PriceperGBperday = float(file.read())
except: 
  print('failed')
try: 
 with open('PriceperGBbutFIAT.txt','r') as file:
  PriceperGBbutFIAT = float(file.read())
except: 
  print('failed')
try: 
 with open('RAMPRICEPERGB.txt','r') as file:
  RAMPRICEPERGB = float(file.read())
except: 
  print('failed')
try: 
 with open('RAMPRICEPERGBFIAT.txt','r') as file:
  RAMPRICEPERGBFIAT = float(file.read())
except: 
  print('failed')
try: 
 with open('DATATRANSFERPRICEPERGB.txt','r') as file:
  DATATRANSFERPRICEPERGB = float(file.read())
except: 
  print('failed')
try: 
 with open('DATATRANSFERPRICEPERGBFIAT.txt','r') as file:
  DATATRANSFERPRICEPERGBFIAT = float(file.read())
except: 
  print('failed')
try: 
 with open('VCPUPRICE.txt','r') as file:
  VCPUPRICE = float(file.read())
except: 
  print('failed')
try: 
 with open('VCPUPRICEFIAT.txt','r') as file:
  VCPUPRICEFIAT = float(file.read())
except: 
  print('failed')

try: 
 with open('DATATRANSFERPOWER.txt','r') as file:
  DATATRANSFERPOWER = int(file.read())
except: 
  print('failed')
try: 
 with open('SPECIALPORT.txt','r') as file:
  SPECIALPORT = int(file.read())
except: 
  print('failed')
try: 
 with open('seed_phrase.txt','r') as file:
  seed_phrase = str(file.read())
except: 
  print('failed')
try: 
 with open('Variable1.txt','r') as file:
  Variable1 = str(file.read())
except: 
  print('failed')
try: 
 with open('Variable2.txt','r') as file:
  Variable2 = str(file.read())
except: 
  print('failed')
try: 
 with open('Variable3.txt','r') as file:
  Variable3 = str(file.read())
except: 
  print('failed')
try: 
 with open('Variable4.txt','r') as file:
  Variable4 = str(file.read())
except: 
  print('failed')
try: 
 with open('Variable5.txt','r') as file:
  Variable5 = str(file.read())
except: 
  print('failed')
try: 
 with open('PlaceHolderText.txt','r') as file:
  PlaceHolderText = str(file.read())
except: 
  print('failed')
try: 
 with open('guestuser.txt','r') as file:
  guestuser = str(file.read())
except: 
  print('failed')
try: 
 with open('guestpass.txt','r') as file:
  guestpass = str(file.read())
except: 
  print('failed')


salt = "22".encode('utf-8')  
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(seed_phrase.encode())

private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),  
    ec.SECP256R1(),  
    backend=default_backend()
)

private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key3333333 = private_key3333.public_key()
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Print or save the private and public keys

import secrets
import string

def createseedphrase(length=18):
    charset = string.ascii_letters + string.digits  # a-zA-Z0-9
    return ''.join(secrets.choice(charset) for _ in range(length))
def createvmstuff(vm_name):
    leterstring = createseedphrase()
    VMDATALIST[leterstring] = {"vmname":vm_name,"Completed":False,"PublicKey":"","PrivateKey":"","IP":"","WalletName":"","Active":True}
    listofkeyeys[selfnum] = {"key":leterstring}
    VMDATALIST2[vm_name] = {"String":leterstring}
    seed_phrase = leterstring

# Derive a cryptographic key from the seed phrase
    seed_key = hashlib.sha256(seed_phrase.encode()).digest()

# Generate a private key
    private_key3333 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # Adjust the key size as needed
)

# Serialize the private key
    private_pem = private_key3333.private_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PrivateFormat.PKCS8,
     encryption_algorithm=serialization.NoEncryption(),
    )

# Generate a corresponding public key
    public_key3333333 = private_key3333.public_key()

# Serialize the public key
    public_pem = public_key3333333.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    VMDATALIST[leterstring]["PublicKey"] = public_key3333333
    VMDATALIST[leterstring]["PrivateKey"] = private_key3333


def get_disk_info1():
   
    partitions = psutil.disk_partitions()
    table = []
    for partition in partitions:
      try:
        usage = psutil.disk_usage(partition.mountpoint)
        print(f"Device: {partition.device}")
        table.append(str(partition.device))
      except:
          print("YOUR MOM")
    return table
def get_disk_info2():
    partitions = psutil.disk_partitions()
    tablething = {}
    for partition in partitions:
     try:
         availablespace = psutil.disk_usage(partition.device)
         tablething[str(partition.device)] = {"availabledata":availablespace.free}
     except:
         lol=True
    return tablething

amountofstuff = 0
for item in letterstring:
    letterdict[amountofstuff] = item
    amountofstuff+=1
class DiskBackedDict:
    def __init__(self, db_file):
        self.conn=sqlite3.connect(db_file)
        self.database = db_file
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS kv_store (
                            key TEXT PRIMARY KEY,
                            value BLOB)''')
        self.conn.commit()

    def __getitem__(self, key):
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM kv_store WHERE key = ?", (key,))
        result = cursor.fetchone()
        if result:
            return pickle.loads(result[0])
        else:
            raise KeyError(key)

    def __setitem__(self, key, value):
        cursor = self.conn.cursor()
        pickled_value = pickle.dumps(value)
        cursor.execute("INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)", (key, pickled_value))
        self.conn.commit()

    def __delitem__(self, key):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM kv_store WHERE key = ?", (key,))
        self.conn.commit()

    def __contains__(self, key):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM kv_store WHERE key = ?", (key,))
        count = cursor.fetchone()[0]
        return count > 0

    def keys(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT key FROM kv_store")
        return [row[0] for row in cursor.fetchall()]

    def close(self):
        self.conn.close()
    def reopen(self,thedbfile):
     if self.conn is None:
        self.conn = sqlite3.connect(str(self.database))
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kv_store'")
        if cursor.fetchone():
            print("Table already exists. Connection reopened.")
        else:
            self.create_table()
     else:
        print("Connection already open.")
countdownthing = 3
changethat600thing = False
the600thing = 600
POWERFOREVERLABEL = 0
VMDATALIST3 = {}
runthecountdowthing = False
LOOPTHEFILEPRICECHECK = True

def add_file_to_vm(vm_name, file_name,file_data,walletname):
    # Command to copy a file to the VM
    full_path = os.path.join(max_drive, "Wallets")

    if not os.path.exists(full_path):
           os.makedirs(full_path)
    second_path = os.path.join(full_path,str(walletname))
    if not os.path.exists(second_path):
           os.makedirs(second_path)
    second_path = os.path.join(second_path,str(file_name))
    with open(file_name,"wb") as file:
        file.write(file_data)
    addfiles(file_name,vm_name)
def get_ip_address():
    try:
        # Create a socket object
        hostname = socket.gethostname()
        
        # Get the IP address associated with the local hostname
        ip_address = socket.gethostbyname(hostname)
        
        return ip_address
    except Exception as e:
        print("Error: ", e)
        return None

# Call the function to get the IP address
ip = get_ip_address()
DECODEDPEM = public_pem.decode('utf-8')
load_pem_public_key(convertthething(DECODEDPEM.encode('utf-8')).encode('utf-8'),backend=default_backend)
if ip:
    print(f"IP Address: {ip}")
else:
    print("Unable to retrieve the IP address.")
#Main Goal: Complete the transaction verification
#Second Goal: Complete the file system.
#Third Goal: Complete the code system.
def get_human_readable_size(size_bytes):
    # Convert bytes to a human-readable format (e.g., KB, MB, GB, etc.)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
app = Flask(__name__)


if not PriceperGBbutFIAT == "NONE":
 PriceperGBbutFIAT = float(PriceperGBbutFIAT)
def sendNEWPRICE():
 LISTOFPRICES = []
 if not PriceperGBbutFIAT == "NONE":
  
  for item in TABLEOFWEBSITESTOCHECK:
     response = requests.get(item)
     
     if response.status_code==200:
         jsonthing = response.json()
         jsonthing = float(jsonthing["Success"])
         LISTOFPRICES.append(jsonthing)
 AVERAGEPRICEOFLISTPRICES = 0
 for item in LISTOFPRICES:
     AVERAGEPRICEOFLISTPRICES+=item
 AVERAGEPRICEOFLISTPRICES = AVERAGEPRICEOFLISTPRICES/len(LISTOFPRICES)
 NEWPPG = PriceperGBbutFIAT*AVERAGEPRICEOFLISTPRICES
 PriceperGB = NEWPPG*(10**8)
 PriceperGBperday = math.floor(PriceperGB)
# Make a request to the webpage
#Remember to add the registering to the transactions thing later on, sillyx-sillyx
if PriceperGBbutFIAT == "NONE":
    with open("pricepergbbutfiat.txt","w") as file:
        file.write(str(PriceperGB)) 
else:
     with open("pricepergbbutfiat.txt","w") as file:
        file.write(str(PriceperGBbutFIAT)) 

def sendNEWRAMPRICE():
 if not RAMPRICEPERGBFIAT == -1:
  LISTOFPRICES = []
  for item in TABLEOFWEBSITESTOCHECK:
     response = requests.get(item)
     if response.status_code==200:
         jsonthing = response.json()
         jsonthing = float(jsonthing["Success"])
         LISTOFPRICES.append(jsonthing)
  AVERAGEPRICEOFLISTPRICES = 0
  for item in LISTOFPRICES:
     AVERAGEPRICEOFLISTPRICES+=item
  AVERAGEPRICEOFLISTPRICES = AVERAGEPRICEOFLISTPRICES/len(LISTOFPRICES)

  NEWPPG = RAMPRICEPERGBFIAT*AVERAGEPRICEOFLISTPRICES
  RAMPRICEPERGB = NEWPPG*(10**8)
  RAMPRICEPERGB = math.floor(RAMPRICEPERGB)
if RAMPRICEPERGBFIAT == -1:
    with open("rampricepergbbutfiat.txt","w") as file:
        file.write(str(RAMPRICEPERGB)) 
else:
     with open("rampricepergbbutfiat.txt","w") as file:
        file.write(str(RAMPRICEPERGBFIAT)) 


def sendNEWDATATRANSFERPRICE():
 if not DATATRANSFERPRICEPERGBFIAT == -1:
  LISTOFPRICES = []
  for item in TABLEOFWEBSITESTOCHECK:
     response = requests.get(item)
     if response.status_code==200:
         jsonthing = response.json()
         jsonthing = float(jsonthing["Success"])
         LISTOFPRICES.append(jsonthing)
  AVERAGEPRICEOFLISTPRICES = 0
  for item in LISTOFPRICES:
     AVERAGEPRICEOFLISTPRICES+=item
  AVERAGEPRICEOFLISTPRICES = AVERAGEPRICEOFLISTPRICES/len(LISTOFPRICES)

  NEWPPG = DATATRANSFERPRICEPERGBFIAT*AVERAGEPRICEOFLISTPRICES
  DATATRANSFERPRICEPERGB = NEWPPG*(10**8)
  DATATRANSFERPRICEPERGB = math.floor(DATATRANSFERPRICEPERGB)
if DATATRANSFERPRICEPERGBFIAT == -1:
    with open("DATATRANSFERpricepergbbutfiat.txt","w") as file:
        file.write(str(DATATRANSFERPRICEPERGB)) 
else:
    with open("DATATRANSFERpricepergbbutfiat.txt","w") as file:
        file.write(str(DATATRANSFERPRICEPERGBFIAT)) 

def sendNEWVCPUPRICE():
 if not VCPUPRICEFIAT == -1:
  LISTOFPRICES = []
  for item in TABLEOFWEBSITESTOCHECK:
     response = requests.get(item)
     if response.status_code==200:
         jsonthing = response.json()
         jsonthing = float(jsonthing["Success"])
         LISTOFPRICES.append(jsonthing)
  AVERAGEPRICEOFLISTPRICES = AVERAGEPRICEOFLISTPRICES/len(LISTOFPRICES)

  AVERAGEPRICEOFLISTPRICES = 0
  for item in LISTOFPRICES:
     AVERAGEPRICEOFLISTPRICES+=item
  NEWPPG = VCPUPRICEFIAT*AVERAGEPRICEOFLISTPRICES
  VCPUPRICE = NEWPPG*(10**8)
  VCPUPRICE = math.floor(VCPUPRICE)
if VCPUPRICEFIAT == -1:
    with open("VCPUPRICEFIAT.txt","w") as file:
        file.write(str(VCPUPRICE)) 
else:
    with open("VCPUPRICEFIAT.txt","w") as file:
        file.write(str(VCPUPRICEFIAT)) 

filey = "files.txt"
vm_name = "testythingy"
os_type = "Linux26_64"
memory_size_mb = 1800
disk_size_mb = 10000
memory_mb = 25
source_file_path = "/home"  # Replace with the path to your source file
destination_folder = "/home/username"  # Replace with the desired destination folder in the VM
isofile = "D:/linuxmint-21.2-xfce-64bit.iso"
readfiledata = "TXT"
fileread = ""
vCPUs = 2
GPUenabled = True


def create_virtual_machine(vm_name, os_type, memory_size_mb, disk_size_mb, iso_file_path, video_memory_mb, vcpu_count, gpu_enabled,walletname):
    createvmstuff(vm_name)
    VMDATALIST[listofkeyeys[selfnum]]["WalletName"] = walletname
    create_vm_command = [
        "VBoxManage",
        "createvm",
        "--name", vm_name,
        "--ostype", os_type,
        "--register"
    ]

    # Execute the VBoxManage command to create the VM
    add_sata_controller_command = [
        "VBoxManage",
        "storagectl", vm_name,
        "--name", "SATA Controller",
        "--add", "sata"
    ]
    subprocess.run(create_vm_command, check=True)

    # Configure memory for the virtual machine
    memory_command = [
        "VBoxManage",
        "modifyvm", vm_name,
        "--memory", str(memory_size_mb)
    ]
    subprocess.run(memory_command, check=True)
    subprocess.run(add_sata_controller_command, check=True)

    # Create a virtual hard disk for the VM
    create_disk_command = [
        "VBoxManage",
        "createhd",
        "--filename", f"{vm_name}.vdi",
        "--size", str(disk_size_mb)
    ]
    subprocess.run(create_disk_command, check=True)

    # Attach the virtual hard disk to the VM
    attach_disk_command = [
        "VBoxManage",
        "storageattach", vm_name,
        "--storagectl", "SATA Controller",
        "--port", "0",
        "--device", "0",
        "--type", "hdd",
        "--medium", f"{vm_name}.vdi"
    ]
    subprocess.run(attach_disk_command, check=True)

    # Configure the boot order to boot from the DVD drive
    boot_order_command = [
        "VBoxManage",
        "modifyvm", vm_name,
        "--boot1", "dvd",
        "--boot2", "disk",
        "--boot3", "none",
        "--boot4", "none"
    ]
    subprocess.run(boot_order_command, check=True)

    # Attach the ISO file as a virtual optical disk with VMSVGA
    attach_iso_command = [
        "VBoxManage",
        "storageattach", vm_name,
        "--storagectl", "SATA Controller",
        "--port", "1",
        "--device", "0",
        "--type", "dvddrive",
        "--medium", iso_file_path
    ]
    subprocess.run(attach_iso_command, check=True)

    # Configure video memory with VMSVGA
    video_memory_command = [
        "VBoxManage",
        "modifyvm", vm_name,
        "--graphicscontroller", "vmsvga",
        "--vram", str(video_memory_mb)
    ]
    subprocess.run(video_memory_command, check=True)

    # Configure vCPUs
    vcpu_command = [
        "VBoxManage",
        "modifyvm", vm_name,
        "--cpus", str(vcpu_count)
    ]
    subprocess.run(vcpu_command, check=True)

    # Enable vGPUs if specified
    if gpu_enabled:
        enable_gpu_command = [
            "VBoxManage",
            "modifyvm", vm_name,
            "--vram", "128",  # Adjust the VRAM size as needed
            "--3daccelerate", "on"
        ]
        subprocess.run(enable_gpu_command, check=True)

    print(f"Virtual machine '{vm_name}' with VMSVGA graphics controller, {vcpu_count} vCPUs, and {'GPU enabled' if gpu_enabled else 'no GPU'} created successfully.")
def modify_vm_storage(vm_name, new_size_gb):
    try:
        # Build the VBoxManage command to modify storage
        command = [
            'VBoxManage',
            'modifyhd',
            vm_name + '.vdi',  # Specify the path to your VM's virtual disk file
            '--resize', str(new_size_gb)  # Set the new size in gigabytes
        ]

        # Run the command using subprocess
        subprocess.run(command, check=True)

        print(f"Storage for VM '{vm_name}' modified successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error modifying storage for VM '{vm_name}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
def add_iso(iso_file_path,vm_name):
    attach_iso_command = [
        "VBoxManage",
        "storageattach", vm_name,
        "--storagectl", "SATA Controller",
        "--port", "1",
        "--device", "0",
        "--type", "dvddrive",
        "--medium", iso_file_path
    ]
    subprocess.run(attach_iso_command, check=True)

def video_memory_command(vm_name,video_memory_mb):
    video_memory_command = [
        "VBoxManage",
        "modifyvm", vm_name,
        "--graphicscontroller", "VBoxVGA",
        "--vram", str(video_memory_mb)
    ]
    subprocess.run(video_memory_command, check=True)
def delete_virtual_machine(vm_name):
    # Command to unregister and delete the virtual machine
    delete_vm_command = [
        "VBoxManage",
        "unregistervm",
        "--delete", vm_name
    ]

    try:
        # Execute the VBoxManage command to delete the VM
        subprocess.run(delete_vm_command, check=True)
        print(f"Virtual machine '{vm_name}' deleted successfully.")
    except subprocess.CalledProcessError:
        print(f"Error: Virtual machine '{vm_name}' not found.")

def delete_file_from_vm(vm_name,file_name):
    IPADDRESSY = VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"]
    data = {"filename":file_name}
    URL = "http://"+IPADDRESSY+":8002/deletefile"
    requests.post(url=URL,json=data)
def start_virtual_machine(vm_name):
    # Command to start the virtual machine
    start_vm_command = [
        "VBoxManage",
        "startvm", vm_name
    ]

    try:
        # Execute the VBoxManage command to start the VM
        subprocess.run(start_vm_command, check=True)
        print(f"Virtual machine '{vm_name}' started successfully.")
    except subprocess.CalledProcessError:
        print(f"Error: Unable to start virtual machine '{vm_name}'.")
def execute_command_on_vm(vm_name, command_to_execute):
     IPADDRESSY = "http://"+VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"]+":8002/executecommand"
     data = {"Command":command_to_execute}
     response2 = requests.post(IPADDRESSY,json=data)

    

def getipthing(vm_name):
    IPADDRESSY = "http://"+VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"]+":8002/getinternetspeed"
    response = requests.get(IPADDRESSY)
    if response.status_code == 200:
        responsey = response.json
        return responsey
def clone_vm(source_vm_name, new_vm_name, new_ram_mb, new_storage_mb, new_vcpus):
  
   if not selfnum in listofkeyeys:
    try:
        # Define the VBoxManage command for cloning the VM
        cmd_clone = [
            'VBoxManage',
            'clonevm',
            source_vm_name,
            '--name', new_vm_name,
            '--register'
        ]
        
        # Run the cloning command using subprocess
        subprocess.run(cmd_clone, check=True)

        # Define the VBoxManage command for modifying the cloned VM
        cmd_modify = [
            'VBoxManage',
            'modifyvm',
            new_vm_name,
            '--memory', str(new_ram_mb),  # Set the new amount of RAM in megabytes
            '--vram', str(new_ram_mb // 2),  # Set video RAM to half of main RAM (adjust as needed)
            '--cpus', str(new_vcpus),  # Set the number of virtual CPUs
        ]
        
        # Run the modification command using subprocess
        subprocess.run(cmd_modify, check=True)

        # Define the VBoxManage command to resize the data storage
        cmd_resize_storage = [
            'VBoxManage',
            'modifymedium', 'disk', new_vm_name + '.vdi',
            '--resize', str(new_storage_mb)  # Set the new storage size in megabytes
        ]
        
        # Run the storage resize command using subprocess
        subprocess.run(cmd_resize_storage, check=True)
        subprocess.run(['VBoxManage', 'guestproperty', 'set', new_vm_name,'VM_NAME', new_vm_name], check=True)
        copy_vmname_to_guest(new_vm_name,guestuser,guestpass)
        print(f"Cloned VM '{source_vm_name}' to '{new_vm_name}' successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
    createvmstuff(new_vm_name)
def changethings(vm_name,max_ram,max_vcpus):
    command = f"VBoxManage modifyvm {vm_name} --memory {max_ram} --cpus {max_vcpus} --hda none --hdb none --hdc none --hdd none --hde none --hdf none --hdg none --hdh none --hdi none --hdj none --hdk none --hdl none --hdm none --hdn none --hdo none --pae on --audio none --usb off"

# Run the command
    try:
     subprocess.run(command, shell=True, check=True)
     print("VM settings updated successfully.")
    except subprocess.CalledProcessError:
     print("Error: Unable to update VM settings.")
try:
 create_virtual_machine(vm_name,os_type,memory_size_mb,disk_size_mb,ISOFILE,memory_mb,vCPUs,GPUenabled)
except:
    print("Error")
try:
 add_iso(ISOFILE,vm_name)
except:
    print("Error")
try:
  video_memory_command(vm_name,memory_mb)
except:
    print("Error")
VMstart = input("Would you like to start the VM?")
if VMstart == "NO" or "No":
 print("No VM started.")
else:
 try:
    start_virtual_machine(vm_name)
 except:
    print("Error")
ISO=""


def stop_virtual_machine(vm_name):
    try:
        # Define the command to stop the VM using VBoxManage
        command = f'VBoxManage controlvm "{vm_name}" poweroff'

        # Execute the command
        subprocess.run(command, shell=True, check=True)

        print(f"Virtual machine '{vm_name}' has been stopped.")
    except subprocess.CalledProcessError:
        print(f"Failed to stop virtual machine '{vm_name}'.")


# After exiting the loop, we can print the collected variables if needed

class serverthing:
    def __init__(self):
        self.transactions = {}
        self.averagetransactionfee = 0
        self.wallets = {}
        self.wallet = ""
        self.codefiles = {}
        self.totalstorage = 0
        self.totalRAM = 0
        self.operationspersecond = 0
        self.serverlist = {}
        self.files = {}
        self.blocklist = DiskBackedDict("blocklist.db")
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        self.blocknum = 1
        self.pendingtransactions = {}
        self.transactionamount = 1
        self.blocktobesent = {}
        self.listofsignatures = []
        self.blockreward = 42000000000000
        self.blocksuntildoom = 6
        self.averagetransactionfee = 0
        self.harddrives = {}
        self.rating = 0
        self.amountofratings = 0 
        self.ratings = {}
        self.totalstorageonthiscomp = 0
        self.othercomputersintheorder = {}
        self.internalizedserver = "12345"
        self.currentsendstreaker = {}
        self.requestlist = {}
        self.serversallowedtoaddtorequestlist = {}
        self.bannedservers = []
        self.serverthingpower = 1
        self.hashstring = ""
        self.verifyingkeyspluswallets = {}
        self.walletnum = 1
        self.blockchainstarttime = 1725148800
        self.pendingfiletransactions = {}
        self.pendingfiletransactionnum = 0
        self.selfverifyingkey = ""
        self.pendingwalletchanges = {}
        self.servernum = 0
        self.filespacedata = {}
        self.filespacedatatransactionnum = 0
        self.altserversonthing = {}
        self.vmdatalistyyy = {}
        self.pendingvmtransactions = {}
        self.pendingvmnum = 0
        self.vmdatalistalt = {}
        self.RAMGB = 0
        self.VCPUS = 0
        self.truevmdatalist = {}
        self.selfip = get_local_ip()
        self.blocknumtransactionnum = 0
        self.pendingtransactionhashlist = {}
        self.superserverlist = {}
        self.specialsuperability = []
        self.specialsuperability.append("192.168.56.1:8002")
        self.superdictdevice = {}
        self.nextproposedblocklist = DiskBackedDict("nextproposedblocklist.db")
        self.loadedblockservers = {}
        self.badservers = {}
        self.itlooped = True
        self.the600thing = 600
        self.thecountdownthing = 3
        self.verifyingkeysperserver = {}
    def setthe600thing(self,new600thing):
        self.the600thing = new600thing
    def listserver(self,server,otherserver,fileprice,verifyingkey,RAMGBPRICE,VCPUPRICE,DATATRANSFERGB,portthing,MINERCHECK,NODECHECK,Verifyingkey2,PROTOCOL):
      if not server+":"+str(portthing) in self.serverlist and not Verifyingkey2 in self.verifyingkeysperserver:
        validip = is_valid_ip(server)
        if validip == False:
            portthing = ""
            self.serverlist[str(server)] ={"server":str(server),"altserver":otherserver,"Fileprice":fileprice,"verifyingkey":verifyingkey,"timeadded":time.time(),"RAMGBPRICE":RAMGBPRICE,"VCPUPRICE":VCPUPRICE,"DATATRANSFERGB":DATATRANSFERGB}
            self.superserverlist[str(server)]={"server":str(server),"altserver":otherserver,"Fileprice":fileprice,"verifyingkey":Verifyingkey2,"portthing":portthing,"timeadded":time.time(),"RAMGBPRICE":RAMGBPRICE,"VCPUPRICE":VCPUPRICE,"DATATRANSFERGB":DATATRANSFERGB,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":PROTOCOL,}
            self.verifyingkeysperserver[Verifyingkey2] = server
        else:
         self.serverlist[str(server)+str(":")+str(portthing)] ={"server":str(server),"altserver":otherserver,"Fileprice":fileprice,"verifyingkey":verifyingkey,"timeadded":time.time(),"RAMGBPRICE":RAMGBPRICE,"VCPUPRICE":VCPUPRICE,"DATATRANSFERGB":DATATRANSFERGB}
         self.superserverlist[str(server)+str(":")+str(portthing)]={"server":str(server),"altserver":otherserver,"Fileprice":fileprice,"verifyingkey":Verifyingkey2,"portthing":portthing,"timeadded":time.time(),"RAMGBPRICE":RAMGBPRICE,"VCPUPRICE":VCPUPRICE,"DATATRANSFERGB":DATATRANSFERGB,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":PROTOCOL}
         self.servernum+=1
         self.verifyingkeysperserver[Verifyingkey2] = server

    def getprotocol(self,server):
        return self.superserverlist[str(server)]["PROTOCOL"] 
    def addtimeaddedtimetoserver(self,server,timeadded):
        try:
         self.serverlist[str(server)]["timeadded"] = timeadded
         self.superserverlist[str(server)]["timeadded"] = timeadded
        except:
         print("What went wrong here???????")
        return "WE DID IT !"
    def getservers2(self):
        return self.superserverlist
    def gethashstringspecial(self):
        
        return str(self.hashstring)

    def gothroughthetransactionlist(self):
     if self.itlooped == False:
         return "WE FAILED!"
     try:
         self.blocklist.close()
     except:
         lol=True
     self.itlooped = False
     self.blocklist = DiskBackedDict("blocklist.db")
     self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
     num_transactions = len(self.pendingtransactions)
     IPADDRESSOFTHESERVER = get_ip_address()
     if num_transactions >200000:
         num_transactions = 200000
     keys_to_delete = []
     self.blocktobesent = {}
     print("PENDING TRANSACTIONS: "+str(self.pendingtransactions))
     print("num_transactions: "+str(num_transactions))
     print("PROPROSEDBLOCKS: "+str(self.proprosedblocks.keys()))

     for i in range(num_transactions):
      print("LOADED!")
      highest_item_key = max(self.pendingtransactions.items(), key=lambda x: x[1]['transactionfee'])[0]
      highest_item_value = self.pendingtransactions.pop(highest_item_key)
      print("THEKEY: "+str(highest_item_key))
      print("THEVALUE: "+str(highest_item_value))
      print(self.pendingtransactions)
    # Use if-elif statements to construct the blockstring
      if highest_item_value["Type"] == 1:
          wallethash = str(highest_item_value["Sender"])+str(highest_item_value["Reciever"])+str(highest_item_value["amountofcoins"])+str(highest_item_value["transactionfee"])+str(highest_item_value["txextra"])
          wallethash = hashlib.sha256(wallethash.encode('utf-8')).hexdigest()

          self.blocktobesent[wallethash] = {"Type":highest_item_value["Type"],"Sender":highest_item_value["Sender"],"Reciever":highest_item_value["Reciever"],"transactionfee":highest_item_value["transactionfee"],"amountofcoins":highest_item_value["amountofcoins"],"txextra":highest_item_value["txextra"],"verifyingsig":highest_item_value["verifyingsig"],"lol":1}
          print(self.blocktobesent[highest_item_key]["txextra"])
          print(self.wallets[highest_item_value["Sender"]]["txextras"])
          print("BLOCKTOBESENT: "+str(self.blocktobesent))
      elif highest_item_value["Type"] == 2:
          self.blocktobesent[str(highest_item_key)] = {"Type":highest_item_value["Type"],"Sender":highest_item_value["Sender"],"Reciever":highest_item_value["Reciever"],"transactionfee":highest_item_value["transactionfee"],"fileprice":highest_item_value["fileprice"],"filesize":highest_item_value["filesize"],"filehash":highest_item_value["filehash"],"daysoflasting":highest_item_value["daysoflasting"],"txextra":highest_item_value["txextra"],"verifyingsig1":highest_item_value["verifyingsig1"],"verifyingsig2":highest_item_value["verifyingsig2"],"lol":1,"txextra2":highest_item_value["txextra2"]}
      elif highest_item_value["Type"] == 3:
         self.blocktobesent[str(highest_item_key)] = {"Type":3,"Sender":highest_item_value["Sender"],"Reciever":highest_item_value["Reciever"],"transactionfee":highest_item_value["transactionfee"],"filepricething":highest_item_value["filepricething"],"filespace":highest_item_value["filespace"],"txextra":highest_item_value["txextra"],"verifyingsig1":highest_item_value["verifyingsig1"],"verifyingsig2":highest_item_value["verifyingsig2"],"daysoflasting":highest_item_value["daysoflasting"],"pendingtransactionnum":highest_item_value["pendingtransactionnum"],"lol":1}
      elif highest_item_value["Type"] == 4:
          self.blocktobesent[str(highest_item_key)] = {"Type":4,"amountofcoins":highest_item_value["amountofcoins"],"Sender":highest_item_value["Sender"],"Reciever":highest_item_value["Reciever"],"verifyingsig1":highest_item_value["verifyingsig1"],"verifyingsig2":highest_item_value["verifyingsig2"],"vmtransactionnum":highest_item_value["vmtransactionnum"],"txextra":highest_item_value["txextra"],"lol":1,"transactionfee":highest_item_value["transactionfee"]}
# Delete the keys after the loop
     for key in keys_to_delete:
      try:
       del self.pendingtransactions[key]
      except:
          print("Missing")
     blockstring = ""
     for item in self.blocktobesent:
      if self.blocktobesent[item]["Type"] == 1:
       blockstring = blockstring+str(self.blocktobesent[item]["Sender"])
       blockstring = blockstring+str(self.blocktobesent[item]["Reciever"])
       blockstring = blockstring+str(self.blocktobesent[item]["amountofcoins"])
       blockstring = blockstring+str(self.blocktobesent[item]["transactionfee"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig"])
       blockstring = blockstring+str(self.blocktobesent[item]["txextra"])
      elif self.blocktobesent[item]["Type"] == 2:
       blockstring = blockstring+str(self.blocktobesent[item]["Sender"])
       blockstring = blockstring+str(self.blocktobesent[item]["Reciever"])
       blockstring = blockstring+str(self.blocktobesent[item]["transactionfee"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig1"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig2"])
       blockstring = blockstring+str(self.blocktobesent[item]["filehash"])
       blockstring = blockstring+str(self.blocktobesent[item]["fileprice"])
       blockstring = blockstring+str(self.blocktobesent[item]["daysoflasting"])
       blockstring = blockstring+str(self.blocktobesent[item]["filesize"])
      elif self.blocktobesent[item]["Type"] == 3:
       blockstring = blockstring+str(self.blocktobesent[item]["Sender"])
       blockstring = blockstring+str(self.blocktobesent[item]["Reciever"])
       blockstring = blockstring+str(self.blocktobesent[item]["transactionfee"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig1"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig2"])
       blockstring = blockstring+str(self.blocktobesent[item]["filepricething"])
       blockstring = blockstring+str(self.blocktobesent[item]["daysoflasting"])
       blockstring = blockstring+str(self.blocktobesent[item]["filespace"])
       blockstring = blockstring+str(self.blocktobesent[item]["pendingtransactionnum"])
      elif self.blocktobesent[item]["Type"] == 4:
       blockstring = blockstring+str(self.blocktobesent[item]["Sender"])
       blockstring = blockstring+str(self.blocktobesent[item]["Reciever"])
       blockstring = blockstring+str(self.blocktobesent[item]["transactionfee"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig1"])
       blockstring = blockstring+str(self.blocktobesent[item]["verifyingsig2"])
       blockstring = blockstring+str(self.blocktobesent[item]["amountofcoins"])
       blockstring = blockstring+str(self.blocktobesent[item]["txextra"])
       blockstring = blockstring+str(self.blocktobesent[item]["vmtransactionnum"])
       # Convert to Mbps
     selfip = get_local_ip()
     if SpecialDevice == 2:
      print("SERVERLIST: "+str(self.serverlist))

      sTF = time.time()-self.serverlist[str(IPADDRESSOFTHESERVER)+":"+str(SPECIALPORT)]["timeadded"]
     else:
      print("SERVERLIST: "+str(self.serverlist))
      sTF = time.time()-self.serverlist[str(SpecialDomain)]["timeadded"]
     if SpecialDevice == 2:
      stuffpower = str(self.blocknum)+str(IPADDRESSOFTHESERVER)
     else:
      stuffpower+=str(self.blocknum)+str(SpecialDomain)
     eothingtoadd2 = hashlib.sha256(stuffpower.encode('utf8')).hexdigest()
     SEALDEAL = int(str(eothingtoadd2),16)
     SEALDEAL = SEALDEAL%7
     signature = private_key3333.sign(
       str(self.wallet).encode('utf-8'),
       ec.ECDSA(hashes.SHA256())
     )
     numthing = sTF*(SEALDEAL+1)
     blockstring+=self.wallet
     blockstring+=str(numthing)
     sha256_hash = hashlib.sha256(blockstring.encode()).hexdigest()

     self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
     
     block_data_copy = copy.deepcopy(self.blocktobesent)
     print("BLOCKDATACOPY: "+str(block_data_copy))
     serverblocklistmust = dict(self.superdictdevice)
     if SpecialDevice == 2:
      serverblocklistmust[str(selfip)+":"+str(SPECIALPORT)] = {"Server":str(selfip)+":"+str(SPECIALPORT),"Sender":self.wallet,"Serverwaittime": numthing}
      print("BLOCKLIST: "+str(serverblocklistmust))
     else:
      print("WELL THIS MAKES ZERO SENSE!")
      serverblocklistmust[str(selfip)] =  {"Server":str(selfip),"Sender":self.wallet,"Serverwaittime": numthing}
     if not sha256_hash in self.proprosedblocks:
      self.proprosedblocks[sha256_hash] = {"Transactionnum":len(block_data_copy),"Count":1,"FirstSender":self.wallet,"Serverip":IPADDRESSOFTHESERVER, "Blockdata":block_data_copy,"Serversthatgotthisblock":serverblocklistmust,"Dateadded":time.time(),"Blockhash":str(sha256_hash),"Timecreated":time.time(),"Timerecieved":time.time(),"serverwaittime":numthing,"BlockDataRecieved":False,"SUPERCHECK":False,"Signature":base64.b64encode(signature).decode('utf-8')}
      print("BLOCKDATA: "+str(self.proprosedblocks[sha256_hash]["Blockdata"]))
      print("Wallet: "+str(self.wallet))
     else:
             newserverblockgetlist = {}
             newserverblockgetlist = dict(self.proprosedblocks[sha256_hash]["Serversthatgotthisblock"])
             print("Length: "+str(len(newserverblockgetlist)))
             newserverblockgetlist[str(selfip)+":"+str(SPECIALPORT)] = {"Server":str(selfip)+":"+str(SPECIALPORT),"Sender":self.wallet,"Serverwaittime": numthing}
             for item in self.superdictdevice:
                 if not item in newserverblockgetlist:
                     newserverblockgetlist[str(item)] = {"Server":str(selfip)+":"+str(SPECIALPORT),"Sender":self.wallet,"Serverwaittime": numthing}

                     print("THERES SOME WORK TO DO!")
             print("NEW SERVER BLOCK GET LIST: "+str(newserverblockgetlist))
             if len(dict(self.proprosedblocks[sha256_hash]["Blockdata"]))>0:
              self.proprosedblocks[sha256_hash] = {"Blockhash": str(self.proprosedblocks[sha256_hash]["Blockhash"]),"Count":int(self.proprosedblocks[sha256_hash]["Count"]) ,"FirstSender":str(self.proprosedblocks[sha256_hash]["FirstSender"]),"Serversthatgotthisblock":newserverblockgetlist,"Timecreated":self.proprosedblocks[sha256_hash]["Timecreated"],"Blockdata":self.proprosedblocks[sha256_hash]["Blockdata"],"Transactionnum":self.proprosedblocks[sha256_hash]["Transactionnum"],"Timerecieved":self.proprosedblocks[sha256_hash]["Timerecieved"],"serverwaittime":self.proprosedblocks[sha256_hash]["serverwaittime"],"BlockDataRecieved":self.proprosedblocks[sha256_hash]["BlockDataRecieved"],"Dateadded":self.proprosedblocks[sha256_hash]["Timecreated"],"SUPERCHECK": self.proprosedblocks[sha256_hash]["SUPERCHECK"],"Signature":base64.b64encode(signature).decode('utf-8')}
             else:

               self.proprosedblocks[sha256_hash] = {"Blockhash": str(self.proprosedblocks[sha256_hash]["Blockhash"]),"Count":int(self.proprosedblocks[sha256_hash]["Count"]) ,"FirstSender":str(self.proprosedblocks[sha256_hash]["FirstSender"]),"Serversthatgotthisblock":newserverblockgetlist,"Timecreated":self.proprosedblocks[sha256_hash]["Timecreated"],"Blockdata":block_data_copy,"Transactionnum":self.proprosedblocks[sha256_hash]["Transactionnum"],"Timerecieved":self.proprosedblocks[sha256_hash]["Timerecieved"],"serverwaittime":self.proprosedblocks[sha256_hash]["serverwaittime"],"BlockDataRecieved":self.proprosedblocks[sha256_hash]["BlockDataRecieved"],"Dateadded":self.proprosedblocks[sha256_hash]["Timecreated"],"SUPERCHECK": self.proprosedblocks[sha256_hash]["SUPERCHECK"],"Signature":base64.b64encode(signature).decode('utf-8')}
     
     print("Time: "+str(self.proprosedblocks[sha256_hash]["serverwaittime"]))
     print("PROPROSEDBLOCKS: "+str(self.proprosedblocks.keys()))
     print ("BLOCKDATA: "+str(self.proprosedblocks[sha256_hash]["Blockdata"]))

     self.proprosedblocks[sha256_hash]["serverwaittime"]+=1

     IPthing = get_local_ip2()
    
     URL = str(httpthingy)+str(IPthing)+":8003/addblockthing"
     data = {"recieved_dict":self.blocktobesent,"selfport":int(SPECIALPORT)}
     self.addblockthing(data)
     retries = 1
     if retries == 1:
      try:
       response = requests.post(URL,json=data)
       retries+=1
      except Exception as e:
         print("Error: "+str(e))
         lol = True
         retries+=1
     print(sha256_hash)
    
     return "WE DID IT!"
    def addnextblocks(self):
       
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        self.nextproposedblocklist = DiskBackedDict("nextproposedblocklist.db")
        listofblockstodelete = []
        newitem = ""
        for item in self.nextproposedblocklist.keys():
            newitem = str(item)
            print(type(self.nextproposedblocklist[item]["Count"]))
            print(type(self.nextproposedblocklist[item]["Transactionnum"]))
            print(type(self.nextproposedblocklist[item]["Timerecieved"]))
            print(type(self.nextproposedblocklist[item]["serverwaittime"]))
            print(type(self.nextproposedblocklist[item]["Timecreated"]))
            if not item in self.proprosedblocks:
             self.proprosedblocks[item] = {"Blockhash": str(self.nextproposedblocklist[item]["Blockhash"]),"Count":int(self.nextproposedblocklist[item]["Count"]) ,"FirstSender":str(self.nextproposedblocklist[item]["FirstSender"]),"Serversthatgotthisblock":dict(self.nextproposedblocklist[item]["Serversthatgotthisblock"]),"Timecreated":str(self.nextproposedblocklist[item]["Timecreated"]),"Blockdata":dict(self.nextproposedblocklist[item]["Blockdata"]),"Transactionnum":dict(self.nextproposedblocklist[item]["Transactionnum"]),"Timerecieved":float(self.nextproposedblocklist[item]["Timerecieved"]),"serverwaittime":float(self.nextproposedblocklist[item]["serverwaittime"]),"BlockDataRecieved":True,"Dateadded":float(self.nextproposedblocklist[item]["Timecreated"]),"SUPERCHECK":False,"Signature":self.nextproposedblocklist[item]["Signature"]}
            else:
                NewServerlist = dict(self.nextproposedblocklist[item]["Serversthatgotthisblock"])
                serverip = str(get_local_ip())
                NewServerlist[serverip+":"+str(SPECIALPORT)] = "YES"
                self.proprosedblocks[item] = {"Blockhash": str(self.nextproposedblocklist[item]["Blockhash"]),"Count":int(self.nextproposedblocklist[item]["Count"]) ,"FirstSender":str(self.nextproposedblocklist[item]["FirstSender"]),"Serversthatgotthisblock":NewServerlist,"Timecreated":str(self.nextproposedblocklist[item]["Timecreated"]),"Blockdata":dict(self.nextproposedblocklist[item]["Blockdata"]),"Transactionnum":dict(self.nextproposedblocklist[item]["Transactionnum"]),"Timerecieved":float(self.nextproposedblocklist[item]["Timerecieved"]),"serverwaittime":float(self.nextproposedblocklist[item]["serverwaittime"]),"BlockDataRecieved":True,"Dateadded":float(self.nextproposedblocklist[item]["Timecreated"]),"SUPERCHECK":False,"Signature":self.nextproposedblocklist[item]["Signature"]}
            listofblockstodelete.append(item)
            print("SErVERS IN THE BLOCK: "+str(self.nextproposedblocklist[item]["Serversthatgotthisblock"]))
        for item in listofblockstodelete:
         del self.nextproposedblocklist[item]
        if not newitem == "":
         print("SERVERS IN THE BLOCK: "+str(self.proprosedblocks[newitem]["Serversthatgotthisblock"]))
        print("ADDED NEXT BLOCKS!")
        return "WE DID IT!"
    def addtimeaddedtoserver(self,Server,time):
        print("Serverlist: "+str(self.serverlist))
        self.serverlist[str(Server)]["Timeadded"] =float(time)
        return "Well ok!"
    def addblockthing(self,data,signature):
     received_dict = data["recieved_dict"]
     portnum = data["selfport"]
     procedureblock = Procedures()
     blockstring = ""
     servers = self.getservers()
     serverlen = len(servers)

     blocksendmore = procedureblock.getthatblockaccepted(received_dict)
     for item in blocksendmore["Blockstuff"]:
      if blocksendmore["Blockstuff"][item]["Type"] == 1:
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Sender"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Reciever"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["amountofcoins"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["transactionfee"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["txextra"])
      elif blocksendmore["Blockstuff"][item]["Type"] == 2:
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Sender"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Reciever"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["transactionfee"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig1"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig2"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["filehash"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["fileprice"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["daysoflasting"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["filesize"])
      elif blocksendmore["Blockstuff"][item]["Type"] == 3:
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Sender"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Reciever"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["transactionfee"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig1"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig2"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["filepricething"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["daysoflasting"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["filespace"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["pendingtransactionnum"])
      elif blocksendmore["Blockstuff"][item]["Type"] == 4:
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Sender"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["Reciever"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["transactionfee"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig1"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["verifyingsig2"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["amountofcoins"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["txextra"])
       blockstring = blockstring+str(blocksendmore["Blockstuff"][item]["vmtransactionnum"])

     dashhash = hashlib.sha256(blockstring.encode()).hexdigest()

     wallet = self.getselfwallet()
     if SpecialDevice == 2:
      data = {
       "hash": dashhash,
       "Firstsender": wallet,
       "Serverip": str(get_local_ip()),
       "Timecreated": blocksendmore["Obtainmentdate"],
       "NodesPassedThrough": 0,
       "Signature":signature

      }
     else:
      data = {
       "hash": dashhash,
       "Firstsender": wallet,
       "Serverip": str(SpecialDomain),
       "Timecreated": blocksendmore["Obtainmentdate"],
       "NodesPassedThrough": 0,
       "Signature":signature

      }
     url1num = random.randint(0,serverlen-1)
     url2num = random.randint(0,serverlen-1)
     CHECKED = True
     servertodelete = 0
     for item in servers:
         if servers[item] == SpecialDomain:
             servertodelete = item
     del servers[servertodelete]
     if SpecialDevice == 2:
      NEWDATA = {"Hash":data["hash"],"Port":str(portnum),"Type": int(SpecialDevice)}
     else:
      NEWDATA = {"Hash":data["hash"],"Port":str(portnum),"Type": int(SpecialDevice),"Domain":SpecialDomain}
     print("Servers: "+str(servers))
     try:
       CHECK = requests.post(self.getprotocol(servers[int(url1num)])+str(servers[int(url1num)])+"/checkforblockexistence",json=NEWDATA)
       print("CHECK:"+str(CHECK))

       CHECK = CHECK.json()
       print("CHECK: "+str(CHECK))
       CHECK = CHECK["Success"]
       print("CHECK:"+str(CHECK))

       if CHECK == "YES":
        if url1num<serverlen:
         url1num+1
        elif url1num>=serverlen:
         url1num+=-1
       supercheck = True
       try:
         servers[int(url1num)]
       except:
         supercheck=False
       if supercheck == False:
         print("NOCROWN")
         print("URL1NUM: "+str(url1num))
         return "WHERE'S MY CROWN"
     except Exception as e:
       print("ERROR: "+str(e))
     with open("Openthis4.txt","w") as file:
         file.write("Got to here")
     try:
       CHECK = requests.post(self.getprotocol(servers[int(url2num)])+str(servers[int(url2num)])+"/checkforblockexistence",json=NEWDATA)
       print("CHECK:"+str(CHECK))

       CHECK = CHECK.json()
       print("CHECK: "+str(CHECK))
       CHECK = CHECK["Success"]
       print("CHECK:"+str(CHECK))

       if CHECK == "YES":
        if url2num<serverlen:
         url2num+1
        elif url2num>=serverlen:
         url2num+=-1
        supercheck = True
        try:
         servers[int(url2num)]
        except:
         supercheck=False
        if supercheck == False:
         print("NOCROWN2")
         return "FAILED"
     except Exception as e:
        print("ERROR2: "+str(e))
     with open("Openthis3.txt","w") as file:
         file.write("Got to here")
     try:
        CHECK = requests.post(self.getprotocol(servers[int(url1num)])+str(servers[int(url1num)])+"/checkforblockdatainthing",json=NEWDATA)
        print("CHECK:"+str(CHECK))

        CHECK = CHECK.json()
        print("CHECK:"+str(CHECK))

        CHECK = CHECK["Success"]
        print("CHECK:"+str(CHECK))
        if CHECK == "YES":
         if url1num<serverlen:
          url1num+1
         elif url1num>=serverlen:
          url1num+=-1
        supercheck = True
        try:
         servers[int(url1num)]
        except:
         supercheck=False
        if supercheck == False:
         print("NOCROWN2")
     except Exception as e:
        print("ERROR3: "+str(e))
     with open("Openthis2.txt","w") as file:
         file.write("Got to here")
     try:
        CHECK = requests.post(self.getprotocol(servers[int(url2num)])+str(servers[int(url2num)])+"/checkforblockdatainthing",json=NEWDATA)
        print("CHECK:"+str(CHECK))

        CHECK=CHECK.json()
        print("CHECK:"+str(CHECK))

        CHECK = CHECK["Success"]
        print("CHECK:"+str(CHECK))

        if CHECK == "YES":
         if url2num<serverlen:
          url2num+1
         elif url2num>=serverlen:
          url2num+=-1
         supercheck = True
        try:
         servers[str(url2num)]
        except:
         supercheck=False
        if supercheck == False:
         print("NOCROWN")
     except Exception as e:
        print("ERROR4: "+str(e))
     with open("Openthis.txt","w") as file:
         file.write("Got to here")
     if url1num == url2num:
        if url2num+1<serverlen:
         url2num+=1
        elif url2num+1>= serverlen:
         url2num+=-1
     else:
        with open("nooooooo.txt","w") as file:
            file.write("URL HERE!")
     servers=servers
     if url1num<0:
        url1num = 0
     if url2num<0:
        url2num = 0
     if not url1num in servers:
         url1num-=1
     if not url2num in servers:
         url2num-=1
     if serverlen == 1:
         url1num = 0
         url2num = 0
     with open("Openthis0.txt","w") as file:
         file.write("Got past here.")
     if not url1num in servers:
         with open("serversoverherecheck.txt","w") as file:
             file.write(str(servers))
         if not len(servers) == 0:
          for item in servers:
             url1num = item
             break
         else:
          url1num = "DONOTUSE"
     url1 = ""
     if not url1num == "DONOTUSE":
      url1 = "http://"+str(servers[int(url1num)])+"/recieveblockdata1"
     else:
      url1 = ""
     url2 = ""
     try:
      url2 = "http://"+str(servers[int(url2num)])+"/recieveblockdata1"
     except:
        with open("Urlhere.txt","w") as file:
            file.write("URL HERE!")
     try:
        with open("NotThis.txt","w") as file:
            file.write("Starts here")
        response = requests.post(url1, json=data)
        with open("Pastthis.txt","w") as file:
            file.write("Past this")
        print(response.status_code)
        if not url2.find("http") == -1:
         response2 = requests.post(url2,json=data)
        with open("Pastthis2.txt","w") as file:
            file.write("Past this")
        with open("NotThat.txt","w") as file:
            file.write("Got here so not that")
        url1 = ""
        try:
         url1 = "http://"+str(servers[str(url1num)])+"/recieveblockdata2"
        except:
         lol=True
        with open("Pastthis3.txt","w") as file:
            file.write("Past this")
        if not url2.find("http") == -1:
         response2 = requests.post(url2,json=data)
         print(response2.status_code)

        url2 = ""
        try:
         url2 = "http://"+str(servers[str(url2num)])+"/recieveblockdata2"
        except:
         lol = True
        with open("Pastthis4.txt","w") as file:
            file.write("Past this")
        Dataset = {"blockdata":dict(blocksendmore["Blockstuff"])}
        if not url1 == "":
         responsee = requests.post(url1,json=Dataset)
        with open("Pastthis5.txt","w") as file:
            file.write("Past this")
        if not url2.find("http") == -1:
         responsee2 = requests.post(url2,json=Dataset)
        with open("Pastthis6.txt","w") as file:
            file.write("Past this")
        with open("Foundthetest.txt","w") as file:
            file.write("Found it.")
        return "Great"
     except Exception as e:
        print("ERROR433: "+str(e))
        with open("Erroroverherecheckrightnow.txt","w") as file:
            file.write(str(e))
        lol=True
        return "Oh crap."
    def findserver(self,wallet):
        for item in self.superserverlist:
            if str(self.superserverlist[item]["verifyingkey"]) == str(self.wallets[wallet]["verifyingkeysummoningthing"]):
                return item
            else:
               with open("verifyingkeything.txt","w") as file:
                   file.write(str(self.wallets[wallet]["verifyingkeysummoningthing"]))
               with open("verifyingkeything2.txt","w") as file:
                   file.write(str(self.superserverlist[item]["verifyingkey"]))
    def acceptablockpuppy(self):
      self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
      print("PROPROSEDBLOCKS: "+str(self.proprosedblocks.keys()))
      for item in self.proprosedblocks.keys():
        
         self.proprosedblocks[item] = {"Blockhash": str(self.proprosedblocks[item]["Blockhash"]),"Count":int(self.proprosedblocks[item]["Count"]) ,"FirstSender":str(self.proprosedblocks[item]["FirstSender"]),"Serversthatgotthisblock":self.proprosedblocks[item]["Serversthatgotthisblock"],"Timecreated":self.proprosedblocks[item]["Timecreated"],"Blockdata":self.proprosedblocks[item]["Blockdata"],"Transactionnum":self.proprosedblocks[item]["Transactionnum"],"Timerecieved":self.proprosedblocks[item]["Timerecieved"],"serverwaittime":self.proprosedblocks[item]["serverwaittime"],"BlockDataRecieved":self.proprosedblocks[item]["BlockDataRecieved"],"Dateadded":self.proprosedblocks[item]["Timecreated"],"SUPERCHECK":True,"Signature":self.proprosedblocks[item]["Signature"]}
      self.itlooped = True

      self.blocktobesent = {}

      selfip = get_local_ip()
      runthecountdownthing = False
      transactionfee = 0
      print("THE BLOCK HAS STARTED") 
      self.blocklist = DiskBackedDict("blocklist.db")
      self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
      
      print(self.proprosedblocks.keys())
      highest_item = ""
      for item in self.proprosedblocks.keys():
          print("ITEM: "+str(self.proprosedblocks[item]))
      try:
       highest_item = max(self.proprosedblocks.keys(), key=lambda x: self.proprosedblocks[x]['serverwaittime'])
       print(highest_item)
       print(self.proprosedblocks[highest_item]["FirstSender"])
      except:
          print("lol")
      if self.proprosedblocks[highest_item]["Blockhash"] == "":
       blockneostring = ""
       blockneohash = hashlib.sha256(blockneostring.encode("utf-8")).hexdigest()
       self.proprosedblocks[highest_item]["Blockhash"] = str(blockneohash)
      isblockvalid = True
      try:
       DICTX = {}
       DICTX["YES"]=self.proprosedblocks[highest_item]["FirstSender"]
       DICTX["YES"]=self.proprosedblocks[highest_item]["Dateadded"]
       DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"]
       DICTX["YES"]=self.proprosedblocks[highest_item]["Signature"]
      except Exception as e:
        isblockvalid = False
        print("ERROR ERROR PUMPKIN TERROR!:"+str(e))
      print("BLOCKDATA: "+str(self.proprosedblocks[highest_item]["Blockdata"]))

      totaltransactions = 0
      oneswithinternetspeed = 0
      
      
      LISTOFSERVERSTOCHECKTHINGSFROM = {}
      for item in self.proprosedblocks.keys():
        try:
          for itemm in self.proprosedblocks[item]["Serversthatgotthisblock"]:
             if not itemm in LISTOFSERVERSTOCHECKTHINGSFROM:
              LISTOFSERVERSTOCHECKTHINGSFROM[str(itemm)] = {"Exists":"Yes"}
              if itemm in self.badservers:
                  del self.badservers[itemm]

        except Exception as e:
            print("ISSUE: "+str(e))
      deletethoseservers = []
      print("LISTOFSERVERSTOCHECKTHINGSFROM: "+str(LISTOFSERVERSTOCHECKTHINGSFROM))
      for item in self.serverlist:
          print("GOING THROUGH HERE!")
          if not item in LISTOFSERVERSTOCHECKTHINGSFROM:
              if item in self.badservers:
                  self.badservers[item]["Times"]+=1
                  if self.badservers[item]["Times"]>=3:
                      deletethoseservers.append(item)
                      print("SERVER ADDED")
                  else:
                      print("NOT THERE YET!")
              else:
                  print("What")
                  self.badservers[item] = {"Times":1}
     
      for item in deletethoseservers:
          del self.serverlist[item]
          print("DELETED A SERVER")
      print("BLOCKDATA: "+str(self.proprosedblocks[highest_item]["Blockdata"]))
      print("Blocknum: "+str(self.blocknum))
      self.blocklist[self.blocknum] = {"Dateadded":0,"BlockData":{},"Blockhash":"","FirstSender":"","Signature":""}
      self.blocklist[self.blocknum]["Dateadded"] = time.time()
      transactiontotal = 0
      try:
       self.blocklist[self.blocknum]["Blockhash"] =  self.proprosedblocks[highest_item]["Blockhash"]
       self.blocklist[self.blocknum]["FirstSender"] =  self.proprosedblocks[highest_item]["FirstSender"]
       signature = self.blocklist[self.blocknum]["Signature"]

      except Exception as e:
          print("Supererror: "+str(e))
          isblockvalid = False
      newwalletlist = {}
      publickeything = self.wallets[self.proprosedblocks[highest_item]["FirstSender"]]["verifyingkey"]
      signature = self.proprosedblocks[highest_item]["Signature"]
      try:
                publickeything.verify(
                   base64.b64decode(signature),
                   self.proprosedblocks[highest_item]["FirstSender"].encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
      except Exception as e:
          isblockvalid = False
      while isblockvalid == False:
          print("THE BLOCK'S NOT VALID!")
          del self.proprosedblocks[highest_item]

          highest_item = max(self.proprosedblocks.keys(), key=lambda x: self.proprosedblocks[x]['serverwaittime'])
          publickeything = self.wallets[self.proprosedblocks[highest_item]["FirstSender"]]["verifyingkey"]
          try:
                publickeything.verify(
                   base64.b64decode(signature),
                   self.proprosedblocks[highest_item]["FirstSender"].encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                isblockvalid = True
                
          except Exception as e:
           isblockvalid = False



      print("Highestitem: "+str(highest_item))
      print("BLOCKDATA: "+str(self.proprosedblocks[highest_item]["Blockdata"]))
      for item in self.proprosedblocks[highest_item]["Blockdata"]:
       validornot = False
       print("WERE THERE")

       try:
           DICTX = {}
           DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] 
       except:
           isblockvalid = False
       if self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 1:
         print("Yes")
         keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig","transactionfee","lol"}  # Define keys that should be kept
         print("SIGNATURE: "+str(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig"]))
         try:
          signature = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig"])
         except:
             self.proprosedblocks[highest_item]= {"serverwaittime":0}
             newwalletlist = {}
             isblockvalid = False
             break
         print("SIGNATURE: "+str(signature))
         keys_to_remove = [key for key in self.proprosedblocks[highest_item]["Blockdata"][item].keys() if key not in keys_to_keep]
         for key in keys_to_remove:
          self.proprosedblocks[highest_item]["Blockdata"][item].pop(key, None)
          self.proprosedblocks[highest_item]  = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
         try:
            DICTX = {}
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["Type"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig"]
            DICTX["YES"]=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
         except:
          self.proprosedblocks[highest_item]  = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
         self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]=remove_sql(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])

         try:
          if not self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"] in newwalletlist:
            coins = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]
            txextras = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]
            newwalletlist[str(self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"])] = {"Coins":int(coins),"txextras":dict(txextras)}
         except:
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
         if self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]:
            print("FOUND IT")
         if newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"] >= (self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"] + self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]) and not self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"] and self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]%1==0 and self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]%1==0 and len(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])==10 and self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]>0:
            print("YEA")
            print(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])
            publickeything = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["verifyingkey"]
            print(publickeything)
            transactionfeedevice = str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            if str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]).find(".") == -1:
                transactionfeedevice= transactionfeedevice+str(".0")
            messagething = str(self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]) + str(self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]) + str(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]) + str(transactionfeedevice) + str(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])
            print(signature)
            message = messagething.encode('utf-8')
            print(messagething)
            try:
                publickeything.verify(
                   signature,
                   message,
                   ec.ECDSA(hashes.SHA256())
                )
                print("Working")
            except Exception as e:
                print("Wrong thing")
                print("ERRORERROR: "+str(e))
                self.proprosedblocks[highest_item]  = {"serverwaittime":0}
                newwalletlist = {}
                isblockvalid = False
                break
            totaltransactions += 1
            transactionfee += self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            validornot = True
            try:
                int(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"])
                int(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            except:
                isblockvalid = False
                newwalletlist = {}
                del self.blocklist[self.blocknum]
                del self.proprosedblocks[highest_item]
                break
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"] += -(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"] + self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = {"yes"}
            if not self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"] in self.pendingwalletchanges:
                           self.pendingwalletchanges[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]] = {"Coins":self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]["Coins"],"txextras":self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]["txextras"]}
            self.pendingwalletchanges[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+=(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"])


         else:
            self.proprosedblocks[highest_item]  = {"serverwaittime":0}
            newwalletlist = {}
            isblockvalid = False
            break
            
       elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 2:
         

         keys_to_keep = {'Type', 'fileprice',"Sender","Reciever","txextra","verifyingsig1","transactionfee","filesize","txextra2","verifyingsig2","filehash","filesize","daysoflasting","lol"}  # Define keys that should be kept
         keys_to_remove = [key for key in self.proprosedblocks[highest_item]["Blockdata"][item].keys() if key not in keys_to_keep]
         for key in keys_to_remove:
          self.proprosedblocks[highest_item]["Blockdata"][item].pop(key, None)
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
         try:
            DICTX = {}
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Type"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["txextra2"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["filesize"]
            DICTX["YES"] =self.proprosedblocks[highest_item]["Blockdata"][item]["filehash"]
         except:
             self.proprosedblocks[highest_item] = {"serverwaittime":0}
             newwalletlist = {}
             isblockvalid = False
             break
         self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]= remove_sql(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])
         self.proprosedblocks[highest_item]["Blockdata"][item]["txextra2"]= remove_sql(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra2"])

         print("Started Up")
         try:
           int(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
           int(self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"])
         except:
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
         try:
          if not self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"] in newwalletlist:
            coins = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]
            txextras = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
            print(newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]])
          if not self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"] in newwalletlist:
            coins = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]
            txextras = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"]
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]] = {"Coins":int(coins),"txextras":dict(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"])}
         except Exception as E:
             print("MISSION FAILED")
             self.proprosedblocks[highest_item] = {"serverwaittime":0}
             newwalletlist = {}
             print(str(E)+"ERROR")
             isblockvalid = False
             break
         verifythis = str(self.proprosedblocks[highest_item]["Blockdata"][item]["filesize"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["daysoflasting"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["filehash"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
         print("VERIFYTHISPART2: "+str(verifythis))
         verifythis2 = str(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra2"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])+".0"         
         print("Part2: "+str(verifythis2))
         print("SIGNATURE1: "+str(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"]))
         print("SIGNATURE2: "+str(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"]))
         signature = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"])
         signature2 = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"])
         print("SIGNATURE: "+str(signature))
         print("SIGNATURE2: "+str(signature2))

         publickeything = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["verifyingkey"]
         publickeything2 = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["verifyingkey"]
         TRUEPOWERTHING = False
         TRUEPOWERTHING2 = False
         if not self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]< newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"] or self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"] or self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"] or not len(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra2"]) == 10 or not self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]%1==0 or not self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]%1 == 0 and self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]>0 and self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]>0:
            TRUEPOWERTHING = False
            TRUEPOWERTHING2 = False
            
            isblockvalid = False
            totaltransactions = 0
            transactionfee = 0
           
            print("Reasons for failure:")
    
            if  (self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"] + self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]) > newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]:
             print("Insufficient coins in Sender's wallet")

            if self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in \
             newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]:
             print("txextra already exists in Sender's txextras")

            if self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in \
             newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"]:
             print("txextra already exists in Receiver's txextras")

            if not len(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]) == 10:
             print("Invalid length of txextra")

            if not self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"] % 1 == 0:
             print("Transaction fee is not a whole number")

            if not self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"] % 1 == 0 or \
             self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"] <= 0 or \
             self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"] <= 0:
             print("Invalid file price or transaction fee")

            print("WE MESSED UP")
            del self.proprosedblocks[highest_item]
            del self.blocklist[self.blocknum]
            newwalletlist = {}
         try:
          publickeything.verify(
              signature,
              verifythis2.encode('utf-8'),
              ec.ECDSA(hashes.SHA256())
          )
          TRUEPOWERTHING = True
         except:
           TRUEPOWERTHING = False
           print("MISSION's FAILED AGAIN")
           isblockvalid = False
           totaltransactions = 0
           transactionfee = 0
           newwalletlist = {}
           del self.blocklist[self.blocknum]
           del self.proprosedblocks[highest_item]
           break
         try:
          publickeything2.verify(
             signature2,
             verifythis.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
          )
          TRUEPOWERTHING2 = True
         
         except:
            TRUEPOWERTHING2 = False
            isblockvalid = False
            totaltransactions = 0
            transactionfee = 0
            newwalletlist = {}
            print("NOOOOOOOO!3")
            del self.blocklist[self.blocknum]
            del self.proprosedblocks[highest_item]
            break
         if TRUEPOWERTHING == True and TRUEPOWERTHING2 == True:
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-(self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = "yes"
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = "yes"
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+=self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]
            
            print("IT IS DONE.")
       elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 3:
        print("COME")
        

        try:
            int(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            int(self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"])
        except:
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
        keys_to_keep = {'Type', 'filepricething',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","daysoflasting","filespace","pendingtransactionnum","lol"}  # Define keys that should be kept
        
        truethough = True
        keys_to_remove = [key for key in self.proprosedblocks[highest_item]["Blockdata"][item].keys() if key not in keys_to_keep]
        for key in keys_to_remove:
          self.proprosedblocks[highest_item]["Blockdata"][item].pop(key, None)
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          newwalletlist = {}
          isblockvalid = False
          break
        try:
            DICTX = {}
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Type"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            DICTX["YES"] =  self.proprosedblocks[highest_item]["Blockdata"][item]["filespace"]
            DICTX["YES"] =  self.proprosedblocks[highest_item]["Blockdata"][item]["daysoflasting"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["pendingtransactionnum"]
        except:
             self.proprosedblocks[highest_item] = {"serverwaittime":0}
             newwalletlist = {}
             isblockvalid = False
             break
        self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]= remove_sql(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])
        try:
         if not self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"] in newwalletlist:
            
            coins = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]
            txextras = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
         if not self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"] in newwalletlist:
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]] = {"Coins":int(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]),"txextras":dict(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"])}
        except:
             self.proprosedblocks[highest_item] = {"serverwaittime":0}
             newwalletlist = {}
             isblockvalid = False
             print("MESSUPREASON: 1")
             break
        verifyingkey1 = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["verifyingkey"]
        verifyingkey2 = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["verifyingkey"]
        verifyingsig1 = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"])
        verifyingsig2 = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"])
        verifythis1 = str(self.proprosedblocks[highest_item]["Blockdata"][item]["pendingtransactionnum"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["filespace"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["daysoflasting"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])

        try:
         verifyingkey1.verify(
          verifyingsig1,
          verifythis1.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
        except:
         truethough = False
         print("MESSUPREASON: 2")
        verifythis2 = str(self.proprosedblocks[highest_item]["Blockdata"][item]["pendingtransactionnum"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["filespace"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["daysoflasting"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"])+str(self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"])+self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]+str(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])

        try:
         verifyingkey2.verify(
           verifyingsig2,
           verifythis2.encode('utf-8'),
           ec.ECDSA(hashes.SHA256())
         )
        except:
            print("MESSUPREASON: 3")
            truethough = False
        if truethough == True and newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]>=(self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]) and not self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"] and not self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"] in newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"] and self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]%1==0 and self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]%1==0 and self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]>0 and self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]>0:
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-(self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
            newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+=self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]
            transactionfee+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
        else:
            txextra = self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]
            transactionfee = self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            filepricething = self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]
           
            del self.proprosedblocks[highest_item]
            del self.blocklist[self.blocknum]
            isblockvalid = False
            totaltransactions = 0
            transactionfee = 0
            newwalletlist = {}
            break
       elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 4:
           print("Come")

           keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","vmtransactionnum","lol"}  # Define keys that should be kept
           truepower1 = True
           try:
               int(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"])
               int(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
           except:
            isblockvalid = False
            totaltransactions = 0
            transactionfee = 0
            newwalletlist = {}
            break
           keys_to_remove = [key for key in self.proprosedblocks[highest_item]["Blockdata"][item].keys() if key not in keys_to_keep]
           for key in keys_to_remove:
            self.proprosedblocks[highest_item]["Blockdata"][item].pop(key, None)
            
            truepower1 = False
           try:
            DICTX = {}
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Type"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"]
            DICTX["YES"] = self.proprosedblocks[highest_item]["Blockdata"][item]["vmtransactionnum"]
           except:
               truepower1 = False
           self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]= remove_sql(self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"])

           try:
            if not self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"] in newwalletlist:
            
             coins = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]
             txextras = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"]
             newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
      
            if not self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"] in newwalletlist:
             newwalletlist[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]] = {"Coins":int(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]),"txextras":dict(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"])}
           except:
                      self.proprosedblocks[newhighestitem] = {"serverwaittime":0}
                      newwalletlist = {}
                      isblockvalid = False
                      break
           verifyingkey = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["verifyingkey"]
           verifyingkey2 = self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["verifyingkey"]
           price = self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]
           transactionfee = self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
           txextra = self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]
           verifyingsig = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig1"])
           verifyingsig2 = base64.b64decode(self.proprosedblocks[highest_item]["Blockdata"][item]["verifyingsig2"])
           sender = self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]
           reciever = self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]
           vmtransactionnum = self.proprosedblocks[highest_item]["Blockdata"][item]["vmtransactionnum"]
           
           verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
           try:
               verifyingkey.verify(
                verifyingsig2,
                verifythis2.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
               )
           except:
               print("LMESSUP!@1")
               truepower1 = False
           verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)

           try:
               verifyingkey2.verify(
                verifyingsig,
                verifythis.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
               )
           except:
               print("LMESSUP!@2")
               truepower1 = False
           if truepower1==True and newwalletlist[sender]["Coins"]>=(price+transactionfee) and not txextra in newwalletlist[sender]["txextras"] and not txextra in newwalletlist[reciever]["txextras"] and price%1==0 and transactionfee%1==0:
                newwalletlist[sender]["Coins"]+=-1*(price+transactionfee)
                newwalletlist[reciever]["Coins"]+=price
                newwalletlist[sender]["txextras"][txextra]= "yes"
                newwalletlist[reciever]["txextras"][txextra]= "yes"
           else:
               if truepower1 == False:
                   print("TYPE4VERIFICATIONERROR")
               if newwalletlist[sender]["Coins"]<=(price+transactionfee):
                   print("TYPE4PRICEERROR")
               if txextra in newwalletlist[sender]["txextras"]:
                   print("TYPE4TXEXTRAERROR")
               if txextra in newwalletlist[reciever]["txextras"]:
                   print("TYPE4TXEXTRAERROR2")
               if price%1<0 or price%1>0:
                   print("TYPE4PRICE%ERROR")
               if transactionfee%1>0 or transactionfee%1<0:
                   print("TYPE4TRANSACTIONFEE%ERROR")
               TRUEPOWERTHING = False
               TRUEPOWERTHING2 = False
               del self.proprosedblocks[highest_item]
               del self.blocklist[self.blocknum]
               isblockvalid = False
               totaltransactions = 0
               transactionfee = 0
               newwalletlist = {}
      print("WERE HERE")
      if isblockvalid == True:
          print("Based!")
          hashed = ""

          if self.proprosedblocks[highest_item]["Blockhash"] == "":
              print("HOW????????????????????")
              if len(dict(self.proprosedblocks[highest_item]["Blockdata"])) == 0:
                  print("FAILURE!")
                  hashed = hashlib.sha256(hashed.encode("utf-8")).hexdigest()
                  self.blocklist[self.blocknum] = {"Blockdata":dict(self.proprosedblocks[highest_item]["Blockdata"]),"FirstSender":str(self.proprosedblocks[highest_item]["FirstSender"]),"Blockhash":hashed,"Dateadded":self.proprosedblocks[highest_item]["Dateadded"],"Signature":self.proprosedblocks[highest_item]["Signature"]}
          if not self.blocknum in self.blocklist:
           self.blocklist[self.blocknum] = {"Blockdata":dict(self.proprosedblocks[highest_item]["Blockdata"]),"FirstSender":str(self.proprosedblocks[highest_item]["FirstSender"]),"Blockhash":str(self.proprosedblocks[highest_item]["Blockhash"]),"Dateadded":str(self.proprosedblocks[highest_item]["Dateadded"]),"Signature":self.proprosedblocks[highest_item]["Signature"]}
          elif self.blocklist[self.blocknum]["FirstSender"] == "":
              self.blocklist[self.blocknum] = {"Blockdata":dict(self.proprosedblocks[highest_item]["Blockdata"]),"FirstSender":str(self.proprosedblocks[highest_item]["FirstSender"]),"Blockhash":str(self.proprosedblocks[highest_item]["Blockhash"]),"Dateadded":str(self.proprosedblocks[highest_item]["Dateadded"]),"Signature":self.proprosedblocks[highest_item]["Signature"]}

              print("WHAT HAPPENED HERE???????")
          print("BLOCKLIST: "+str(self.blocklist[self.blocknum]))
          if not str(self.blocklist[self.blocknum]["FirstSender"]) == str(self.proprosedblocks[highest_item]["FirstSender"]):
              print("THIS DOESNT MAKE SENSE!")
          print("FirstSender: "+str(self.blocklist[self.blocknum]["FirstSender"]))
  
              
          self.hashstring = self.hashstring+self.blocklist[self.blocknum]["Blockhash"]
          print("POWER3")
          self.blocknum+=1
          self.blocksuntildoom+=-1
          
          transactionsinthere = 0
          transactionfee = 0
          print("POWER4")
          print("SERVERSTHATGOTHISBLOCK: "+str(self.proprosedblocks[highest_item]["Serversthatgotthisblock"]))
          highest_sender = max(self.proprosedblocks[highest_item]["Serversthatgotthisblock"], key=lambda x: self.proprosedblocks[highest_item]["Serversthatgotthisblock"][x]['Serverwaittime'])
          highest_sender = str(self.proprosedblocks[highest_item]["Serversthatgotthisblock"][highest_sender]["Sender"])
          print("highest_sender: "+str(highest_sender))
          print("WALLETS: "+str(self.wallets))
          if self.blocksuntildoom <= 0 and self.blocknum<100:
           self.blocksuntildoom = 210000
           self.blockreward = 45*(10**8)
          elif self.blocksuntildoom <= 0:
           self.blocksuntildoom = 210000
           self.blockreward = self.blockreward//2
           self.blockreward = round(self.blockreward)
          print("POWER5")
          try:
           self.wallets[highest_sender]["Coins"]+=self.blockreward
          except:
              print("BIG ISSUE!")
          print(self.wallets[self.proprosedblocks[highest_item]["FirstSender"]]["Coins"])
          for item in dict(self.proprosedblocks[highest_item]["Blockdata"]):
            if self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 1:
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+= -1*(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"])
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-1*(self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+=self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]
              print(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"])
              print(self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]])
              self.wallets[highest_sender]["Coins"]+= self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = "yes"
              transactionsinthere+=1

              transactionfee+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 2:
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-1* (self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+= self.proprosedblocks[highest_item]["Blockdata"][item]["fileprice"]
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = "yes"
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]] = "yes"
              self.wallets[highest_sender]["Coins"]+= self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
              transactionsinthere+=1
              transactionfee+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 3:
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-1* (self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+= self.proprosedblocks[highest_item]["Blockdata"][item]["filepricething"]
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
              self.wallets[highest_sender]["Coins"]+= self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
              transactionsinthere+=1
              transactionfee+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            elif self.proprosedblocks[highest_item]["Blockdata"][item]["Type"] == 4:
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["Coins"]+=-1*(self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]+self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"])
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["Coins"]+=self.proprosedblocks[highest_item]["Blockdata"][item]["amountofcoins"]
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
              self.wallets[self.proprosedblocks[highest_item]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[highest_item]["Blockdata"][item]["txextra"]]= "yes"
              self.wallets[highest_sender]["Coins"]+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
              transactionsinthere+=1
              transactionfee+=self.proprosedblocks[highest_item]["Blockdata"][item]["transactionfee"]
            for item in self.proprosedblocks.keys():
             del self.proprosedblocks[item]
          print("POWER6")

          try:
           self.averagetransactionfee = transactionfee/transactionsinthere
          except:
              lol=True
          listofcoinstodelete = {}
          for item in self.proprosedblocks.keys():
              listofcoinstodelete[item] = "Yes"
          for item in listofcoinstodelete:
              del self.proprosedblocks[item]
          self.blocklist.close()
          self.proprosedblocks.close()
          print("HERE######44448")

      else:
         print("DETECTED")
         if len(self.proprosedblocks.keys()) == 0:
             self.blocklist[self.blocknum] = {"Blockdata":{},"Dateadded":time.time(),"Blockhash":"NONE","FirstSender":"NONE"}
             self.blocknum+=1
             self.blocksuntildoom+=-1
             if self.blocksuntildoom == 0 and self.blocknum<100:
              self.blocksuntildoom = 210000
              self.blockreward = 45*(10**8)
             elif self.blocksuntildoom == 0:
              self.blocksuntildoom = 210000
              self.blockreward = self.blockreward//2
              self.blockreward = round(self.blockreward)
             print("Uh oh.")
         else:
          print("OK!")
          self.proprosedblocks[highest_item] = {"serverwaittime":0}
          print(self.proprosedblocks[highest_item]["serverwaittime"])
          self.proprosedblocks[highest_item]["Blockdata"] = {}
          try:
           del self.proprosedblocks[highest_item]["Blockdata"]
          except:
              print("ALREADY GONE!")
          del self.blocklist[self.blocknum]

          for item in newwalletlist:
              del newwalletlist[item]
          oldhighestitem = highest_item
          newwaletlist = set()
          outerflag = False
          isblocktrue = True

          for item in self.proprosedblocks.keys():
               if outerflag == True:
                   break
               newhighestitem = max(self.proprosedblocks.keys(), key=lambda x: self.proprosedblocks[x]['serverwaittime'])
               signature = self.proprosedblocks[newhighestitem]["Signature"]
               try:
                publickeything.verify(
                   base64.b64decode(signature),
                   self.proprosedblocks[newhighestitem]["FirstSender"].encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
               except Exception as e:
                isblocktrue = False
               while isblocktrue == False:
                del self.proprosedblocks[highest_item]

                newhighestitem = max(self.proprosedblocks.keys(), key=lambda x: self.proprosedblocks[x]['serverwaittime'])
                publickeything = self.wallets[self.proprosedblocks[newhighestitem]["FirstSender"]]["verifyingkey"]
                try:
                 publickeything.verify(
                   base64.b64decode(signature),
                   self.proprosedblocks[highest_item]["FirstSender"].encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                 )
                 isblocktrue = True
                
                except Exception as e:
                 isblocktrue = True
               print("NEWHIGHESTITEM: "+str(newhighestitem))
               try:
                 firstsender = dict(self.proprosedblocks[newhighestitem]["FirstSender"])
                 firstsender = firstsender["Success"]
                 print("NEWFIRSTSENDER: "+str(firstsender))
                 self.proprosedblocks[newhighestitem]["FirstSender"] = firstsender
               except:
                 print("BIG ERROR!")
               blockneostring = ""
               blockneohash = hashlib.sha256(blockneostring.encode("utf-8")).hexdigest()
               self.proprosedblocks[newhighestitem]["Blockhash"] = str(blockneohash)
               if newhighestitem == oldhighestitem:
                   print("HOW!")
                   print(self.proprosedblocks)
                   self.proprosedblocks[newhighestitem] = {"serverwaittime":0}
                   print(self.proprosedblocks[newhighestitem]["serverwaittime"])
                   if not self.proprosedblocks[newhighestitem]["serverwaittime"] == 0:
                       print("COMPLETE NONSENSE")
                   return "WE TRIED SO HARD BUT WE COULDNT SUCCEED."
              
               try:
                 transactionsinthere = len(self.proprosedblocks[newhighestitem]["Blockdata"])
               except Exception as e:
                    print("EXCEPTION: "+str(e))
                    self.proprosedblocks[newhighestitem] = {"serverwaittime":0}
                    newwalletlist = {}
                    isblocktrue = False
                    break
               transactionsinthere2 = int(transactionsinthere)
               transactionfeething4 = 0
               print("BLOCKDATA: "+str(self.proprosedblocks[newhighestitem]["Blockdata"]))
               for itemm in self.proprosedblocks[newhighestitem]["Blockdata"]:
                 transactionsinthere-=1
                 print("WE DID IT@~!")
                 
                     
                 if self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"] == 1:
                  print("Yes")
                  keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig","transactionfee","lol"}  # Define keys that should be kept

                  keys_to_remove = [key for key in self.proprosedblocks[newhighestitem]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                  for key in keys_to_remove:
                   if len(keys_to_remove>0):
                    self.proprosedblocks[newhighestitem]["Blockdata"][itemm].pop(key, None)
                    self.proprosedblocks[newhighestitem] = {"serverwaittime":0}
                    newwalletlist = {}
                    isblocktrue = False
                    break
                    print("EEEPICFAIL")

                  try:
                   DICTX = {}
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig"]
                   DICTX["YES"]=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]
                  except:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])
                    print("EEPICFAIL")
                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwaletlist = set()

                    isblocktrue = False
                    break
                  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]= remove_sql(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])

                  try:
                   if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"] in newwalletlist:
                    coins = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]
                    txextras = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]
                    newwalletlist[str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"])] = {"Coins":int(coins),"txextras":dict(txextras)}
                  except:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwaletlist = set()
                    print("EPICFAIL")
                    isblocktrue = False
                    break
                  if self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]:
                   print("FOUND IT")
                   print("NEW WALLET: "+str(newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]))
                  else:
                      print("WHAT HAPPENED!")
                  if newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"] >= (self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"] + self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]) and not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"] and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]%1==0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]%1==0 and len(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])==10 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]>0:
                   print("YEA")
                   print(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])
                   publickeything = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["verifyingkey"]
                   print(publickeything)
                   
                   print(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig"])
                   signature =  base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig"])
                   messagething444 = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])
                   print(signature)
                   messagefind33 = messagething444.find(".")
                   if messagefind33 == -1:
                       messagething444 = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]) + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])+str(".0") + str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])
                   message444 = messagething444.encode('utf-8')
                   print(message444)
                   message444 = messagething444.encode('utf-8')

                   try:
                    publickeything.verify(
                     signature,
                     message444,
                     ec.ECDSA(hashes.SHA256())
                    )
                    print("Working")
                   except Exception as e:
                    print("Wrong thing")
                    print(e)
                    print("SIGNATUREVALUE: "+str(signature))
                    print("MESSAGETHING: "+str(messagething444))
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwaletlist = set()

                    isblocktrue = False
                    break
                    
                   totaltransactions += 1
                   transactionfee += self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]
                   validornot = True
                   try:
                    int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
                    int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                   except:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwaletlist = set()

                    isblocktrue = False
                    break
                   if isblocktrue == True:
                       newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]] = {"yes"}
                       newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]+=int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
                       if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"] in self.pendingwalletchanges:
                           self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]] = {"Coins":self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"],"txextras":self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"]}
                       self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]+=(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
                       print("WALLETDATA: "+str(self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]))
                         
                  else:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])
                    print("EEEEEPICFAIL")
                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                 elif self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"] == 2:
                  print("START THAT UP!!!!")
                  keys_to_keep = {'Type', 'fileprice',"Sender","Reciever","txextra","verifyingsig1","transactionfee","filesize","txextra2","verifyingsig2","filehash","filesize","daysoflasting","lol"}  # Define keys that should be kept
                  keys_to_remove = [key for key in self.proprosedblocks[newhighestitem]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                  for key in keys_to_remove:
                   self.proprosedblocks[newhighestitem]["Blockdata"][itemm].pop(key, None)
                   block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                   block_data = {"serverwaittime":0}
                   self.proprosedblocks[newhighestitem]=block_data
                   newwalletlist = {}
                   isblocktrue = False
                   break
                  print("WERE WINNING!")
                  try:
                   DICTX = {}
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra2"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filesize"]
                   DICTX["YES"] =self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filehash"]
                  except Exception as e:
                    print("THEERROR: "+str(e))
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]= remove_sql(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])
                  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra2"]= remove_sql(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra2"])

                  try:
                   int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                   int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"])
                  except Exception as e:
                   print("THEERROR2: "+str(e))
                   block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                   block_data = {"serverwaittime":0}
                   self.proprosedblocks[newhighestitem]=block_data
                   newwalletlist = {}
                   isblocktrue = False
                   break
                  try:
                   if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"] in newwalletlist:
                    coins = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]
                    txextras = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]
                    newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
                    print(newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]])
                   if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"] in newwalletlist:
                     coins = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]
                     txextras = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"]
                     newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]] = {"Coins":int(coins),"txextras":dict(self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"])}
                  except Exception as E:
                   print("THEERROR3: "+str(e))
                   print("MISSION FAILED")
                   block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                   block_data = {"serverwaittime":0}
                   self.proprosedblocks[newhighestitem]=block_data
                   newwalletlist = {}
                   isblocktrue = False
                   break
                  verifythis = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filesize"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["daysoflasting"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filehash"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                  print("VERIFYTHISPART2: "+str(verifythis))
                  verifythis2 = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra2"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])+".0"         

                  print("Part2: "+str(verifythis2))
                  signature = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"])
                  signature2 = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"])
                  publickeything = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["verifyingkey"]
                  publickeything2 = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["verifyingkey"]
                  TRUEPOWERTHING = False
                  TRUEPOWERTHING2 = False
                  if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]< newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"] or self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"] or self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"] or not len(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra2"]) == 10 or not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]%1==0 or not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]%1 == 0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]>0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]>0:
                   TRUEPOWERTHING = False
                   TRUEPOWERTHING2 = False
                   block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])
                   block_data = {"serverwaittime":0}
                   self.proprosedblocks[newhighestitem]=block_data
                   newwalletlist = {}
                   isblocktrue = False
                   break
                    
                  
                  
                  try:
                    publickeything.verify(
                     signature,
                     verifythis2.encode('utf-8'),
                     ec.ECDSA(hashes.SHA256())
                    )
                    TRUEPOWERTHING = True
                  except Exception as E:
                    print("THEERROR4: "+str(E))
                    TRUEPOWERTHING = False
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                  try:
                    publickeything2.verify(
                     signature2,
                     verifythis.encode('utf-8'),
                     ec.ECDSA(hashes.SHA256())
                    )
                    TRUEPOWERTHING2 = True
         
                  except Exception as E:
                    print("THEERROR5: "+str(E))
                    TRUEPOWERTHING2 = False
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                  if TRUEPOWERTHING == True and TRUEPOWERTHING2 == True:
                   newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]+=-(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                   newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]] = "yes"
                   newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]] = "yes"
                   newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]+=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["fileprice"]
            
                   print("IT IS DONE.")
                 elif self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"] == 3:
                     print("COME")
                     try:
                      int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                      int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"])
                     except:
                      block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                      block_data = {"serverwaittime":0}
                      self.proprosedblocks[newhighestitem]=block_data
                      newwalletlist = {}
                      isblocktrue = False
                      break
                     print("COME2")

                     keys_to_keep = {'Type', 'filepricething',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","daysoflasting","filespace","pendingtransactionnum","lol"}  # Define keys that should be kept
                     print("COME3")

                     truethough = True
                     print("COME4")

                     keys_to_remove = [key for key in self.proprosedblocks[newhighestitem]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                     print("COME5")

                     for key in keys_to_remove:
                      self.proprosedblocks[newhighestitem]["Blockdata"][itemm].pop(key, None)
                      block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                      block_data= {"serverwaittime":0}
                      self.proprosedblocks[newhighestitem]=block_data
                      newwalletlist = {}
                      isblocktrue = False
                      break
                     try:
                      DICTX = {}
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]
                      DICTX["YES"] =  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filespace"]
                      DICTX["YES"] =  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["daysoflasting"]
                      DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["pendingtransactionnum"]
                     except:
                      block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                      block_data = {"serverwaittime":0}
                      self.proprosedblocks[newhighestitem]=block_data
                      newwalletlist = {}
                      isblocktrue = False
                      break
                     self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]= remove_sql(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])

                     try:
                      if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"] in newwalletlist:
            
                       coins = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]
                       txextras = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]
                       newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
                      if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"] in newwalletlist:
                       newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]] = {"Coins":int(self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]),"txextras":dict(self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"])}
                     except:
                      block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                      block_data = {"serverwaittime":0}
                      self.proprosedblocks[newhighestitem]=block_data
                      newwalletlist = {}
                      isblocktrue = False
                      break
                     print("COME6")
                     verifyingkey1 = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["verifyingkey"]
                     verifyingkey2 = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["verifyingkey"]
                     verifyingsig1 = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"])
                     verifyingsig2 = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"])
                     verifythis1 = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["pendingtransactionnum"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filespace"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["daysoflasting"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                     print("COME7")
                     try:
                      verifyingkey1.verify(
                       verifyingsig1,
                       verifythis1.encode('utf-8'),
                       ec.ECDSA(hashes.SHA256())
                      )
                     except:
                      truethough = False
                      print("MESSUPREASON: 2")
                     verifythis2 = str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["pendingtransactionnum"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filespace"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["daysoflasting"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"])+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"])+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]+str(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                     print("COME8")
                     try:
                      verifyingkey2.verify(
                       verifyingsig2,
                       verifythis2.encode('utf-8'),
                       ec.ECDSA(hashes.SHA256())
                      )
                     except:
                      print("MESSUPREASON: 3")
                      truethough = False
                     if truethough == True and newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]>=(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]) and not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"] and not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"] and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]%1==0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]%1==0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]>0 and self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]>0:
                      newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]+=-(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                      newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]]= "yes"
                      newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]]= "yes"
                      newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]+=self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]
                     else:
                      if truethough == False:
                          print("TRUETHOUGHERROR")
                      if newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]<=(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]+self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]):
                          print("COINERROR")
                      if self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]:
                          print("TXEXTRAERROR")
                      if   self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"] in newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"] :
                          print("TXEXTRAERROR2")
                      if  not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]%1==0:
                          print("TRANSACTIONFEE.ERROR")
                      if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]%1==0 :
                          print("FILEPRICETHINGERROR")
                      if self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["filepricething"]<=0:
                          print("ANOTHERFILEPRICETHINGERROR")
                      if self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]<=0:
                          print("ANOTHERTRANSACTIONFEE.ERROR")
                      block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                      block_data = {"serverwaittime":0}
                      self.proprosedblocks[newhighestitem]=block_data
                      newwalletlist = {}
                      isblocktrue = False
                      break
                 elif self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"] == 4:
                  print("Come")
                  keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","vmtransactionnum","lol"}  # Define keys that should be kept
                  truepower1 = True
                  try:
                   int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
                   int(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"])
                  except:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                  keys_to_remove = [key for key in self.proprosedblocks[newhighestitem]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                  for key in keys_to_remove:
                   self.proprosedblocks[newhighestitem]["Blockdata"][itemm].pop(key, None)
                   truepower1 = False
                  try:
                   DICTX = {}
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Type"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"]
                   DICTX["YES"] = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["vmtransactionnum"]
                  except:
                   truepower1 = False
                  self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]= remove_sql(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"])

                  try:
                   if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"] in newwalletlist:
            
                    coins = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["Coins"]
                    txextras = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["txextras"]
                    newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]] = {"Coins":int(coins),"txextras":dict(txextras)}
      
                   if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"] in newwalletlist:
                    newwalletlist[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]] = {"Coins":int(self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]),"txextras":dict(self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"])}
                  except:
                    block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                    block_data = {"serverwaittime":0}
                    self.proprosedblocks[newhighestitem]=block_data
                    newwalletlist = {}
                    isblocktrue = False
                    break
                  verifyingkey = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["verifyingkey"]
                  verifyingkey2 = self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]]["verifyingkey"]
                  price = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"]
                  transactionfee = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["transactionfee"]
                  txextra = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["txextra"]
                  verifyingsig = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig1"])
                  verifyingsig2 = base64.b64decode(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["verifyingsig2"])
                  sender = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Sender"]
                  reciever = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]
                  vmtransactionnum = self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["vmtransactionnum"]
           
                  verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
                  try:
                   verifyingkey.verify(
                    verifyingsig2,
                    verifythis2.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                   )
                  except:
                   print("LMESSUP!@1")
                   truepower1 = False
                  verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)

                  try:
                   verifyingkey2.verify(
                    verifyingsig,
                    verifythis.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                   )
                  except:
                   print("LMESSUP!@2")
                   truepower1 = False
                  if truepower1==True and newwalletlist[sender]["Coins"]>=(price+transactionfee) and not txextra in newwalletlist[sender]["txextras"] and not txextra in newwalletlist[reciever]["txextras"] and price%1==0 and transactionfee%1==0:
                   newwalletlist[sender]["Coins"]+=-1*(price+transactionfee)
                   newwalletlist[reciever]["Coins"]+=price
                   newwalletlist[sender]["txextras"][txextra]= "yes"
                   newwalletlist[reciever]["txextras"][txextra]= "yes"
                  else:
                   if truepower1 == False:
                    print("TYPE4VERIFICATIONERROR")
                   if newwalletlist[sender]["Coins"]<=(price+transactionfee):
                    print("TYPE4PRICEERROR")
                   if txextra in newwalletlist[sender]["txextras"]:
                    print("TYPE4TXEXTRAERROR")
                   if txextra in newwalletlist[reciever]["txextras"]:
                    print("TYPE4TXEXTRAERROR2")
                   if price%1<0 or price%1>0:
                    print("TYPE4PRICE%ERROR")
                   if transactionfee%1>0 or transactionfee%1<0:
                    print("TYPE4TRANSACTIONFEE%ERROR")
                   TRUEPOWERTHING = False
                   TRUEPOWERTHING2 = False
                   block_data = copy.deepcopy(self.proprosedblocks[newhighestitem])

                   block_data = {"serverwaittime":0}
                   self.proprosedblocks[newhighestitem]=block_data
                   newwalletlist = {}
                   isblocktrue = False
                   break
                 outerflag = True
                 if transactionsinthere==0 and isblocktrue == True:
                     break
                     
          if isblocktrue == True:
           transactionfeething = 0 
           highest_sender = max(self.proprosedblocks[highest_item]["Serversthatgotthisblock"], key=lambda x: self.proprosedblocks[highest_item]["Serversthatgotthisblock"][x]['Serverwaittime'])
           highest_sender = str(self.proprosedblocks[highest_item]["Serversthatgotthisblock"][highest_sender]["Sender"])
           for item in self.proprosedblocks[newhighestitem]["Blockdata"]:
           
            if self.proprosedblocks[newhighestitem]["Blockdata"][item]["Type"] == 1:
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["Coins"]+= math.floor( self.proprosedblocks[newhighestitem]["Blockdata"][item]["amountofcoins"])
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["Coins"]+= -math.floor((self.proprosedblocks[newhighestitem]["Blockdata"][item]["amountofcoins"]+ self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]))
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["txextras"][ self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "yes"
              transactiontotal+=1
              transactionfeething+=math.floor( self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"])
              if not self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"] in self.pendingwalletchanges:
                       self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]] = {"Coins":self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"],"txextras":self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["txextras"]}
                       self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]+=(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
              else:
               self.pendingwalletchanges[self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["Reciever"]]["Coins"]+=(self.proprosedblocks[newhighestitem]["Blockdata"][itemm]["amountofcoins"])
              print("WALLETDATA: "+str(self.pendingwalletchanges))
            elif self.proprosedblocks[newhighestitem]["Blockdata"][item]["Type"] == 2:
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["Coins"]+=math.floor(self.proprosedblocks[newhighestitem]["Blockdata"][item]["fileprice"])
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["Coins"]+=-math.floor((self.proprosedblocks[newhighestitem]["Blockdata"][item]["fileprice"]+ self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]))
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "yes"
              self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "yes"
              transactiontotal+=1
              transactionfeething+= self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]
            elif self.proprosedblocks[newhighestitem]["Blockdata"][item]["Type"] == 3:
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["Coins"]+=math.floor(self.proprosedblocks[newhighestitem]["Blockdata"][item]["filepricething"])
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["Coins"]+=-math.floor((self.proprosedblocks[newhighestitem]["Blockdata"][item]["filepricething"]+self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]))
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "yes"
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["txextras"][ self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "yes"
                transactiontotal+=1
                transactionfeething+= self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]
            elif self.proprosedblocks[newhighestitem]["Blockdata"][item]["Type"] == 4:
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["Coins"]+=math.floor(self.proprosedblocks[newhighestitem]["Blockdata"][item]["amountofcoins"])
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["Coins"]+=-math.floor((self.proprosedblocks[newhighestitem]["Blockdata"][item]["amountofcoins"]+self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]))
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Sender"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "Yes"
                self.wallets[self.proprosedblocks[newhighestitem]["Blockdata"][item]["Reciever"]]["txextras"][self.proprosedblocks[newhighestitem]["Blockdata"][item]["txextra"]] = "Yes"
                transactiontotal+=1
                transactionfeething+=self.proprosedblocks[newhighestitem]["Blockdata"][item]["transactionfee"]
           
           try:
            self.averagetransactionfee = transactionsinthere2/transactionfeething
           except:
               lol=True
           self.blocklist[self.blocknum] = {"Blockdata":self.proprosedblocks[newhighestitem]["Blockdata"],"Dateadded":time.time(),"Blockhash":str(newhighestitem),"FirstSender":self.proprosedblocks[newhighestitem]["FirstSender"],"Signature":self.proprosedblocks[newhighestitem]["Signature"]}
           self.hashstring = self.hashstring +self.blocklist[self.blocknum]["Blockhash"]
           self.blocknum+=1
           self.blocksuntildoom+=-1
           print("BLOCKSUNTILDOOM: "+str(self.blocksuntildoom))
           if self.blocksuntildoom <= 0 and self.blocknum<100:
            self.blocksuntildoom = 210000
            self.blockreward = 45*(10**8)
           elif self.blocksuntildoom <= 0:
            self.blocksuntildoom = 210000
            self.blockreward = self.blockreward//2
            self.blockreward = round(self.blockreward)
            self.blocklist.close()
            self.proprosedblocks.close()

           self.wallets[highest_sender]["Coins"]+=self.blockreward
           print("WALLETCOINS: "+str(self.wallets[self.proprosedblocks[newhighestitem]["FirstSender"]]["Coins"]))
           self.wallets[highest_sender]["Coins"]+=transactionfeething
      print("HERE######44444")
      listofcoinstodelete = {}
      self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
      for item in self.proprosedblocks.keys():
              listofcoinstodelete[item] = "Yes"
      for item in listofcoinstodelete:
              del self.proprosedblocks[item]
      self.addnextblocks()

    def getwalletcoins(self):
      print(self.wallets["333"]["Coins"]/(10**8))
    def addtransactionstopendingtransactions(self,wallet1,wallet2,amountofcoins,transactionfee,txextra,verifyingsignature):
     print("IM IN")
     wallethash = str(wallet1)+str(wallet2)+str(amountofcoins)+str(transactionfee)+str(txextra)
     wallethash = hashlib.sha256(wallethash.encode('utf-8')).hexdigest()
     if wallethash in self.pendingtransactions:
         print("MESS UP")
         return "L"
     if not wallet1 in self.pendingwalletchanges:
        coincopy =  dict(self.wallets[wallet1]["txextras"])
        self.pendingwalletchanges[wallet1] = {"Coins":int(self.wallets[wallet1]["Coins"]),"txextras":coincopy}
     if not wallet2 in self.pendingwalletchanges:
        coincopy =  dict(self.wallets[wallet2]["txextras"])
        self.pendingwalletchanges[wallet2] = {"Coins":int(self.wallets[wallet2]["Coins"]),"txextras":coincopy}
     
     if not wallet1 in self.wallets:
         print("MESS UP!")
         return "MESS UP!"
     if not wallet2 in self.wallets:
         print("MESS UP!")
         return "MESS UP!"
     if txextra in self.pendingwalletchanges[wallet1]["txextras"]:
         print("TXEXTRAMEGAFAIL")
         return "L"
     if txextra in self.pendingwalletchanges[wallet2]["txextras"]:
         print("TXEXTRAMEGAFAIL")
         return "L"
     if self.pendingwalletchanges[wallet1]["Coins"]>=(amountofcoins+transactionfee) and amountofcoins>0 and amountofcoins%1==0 and wallet1 in self.wallets and wallet2 in self.wallets and transactionfee%1==0 and transactionfee>0 and not txextra in self.pendingwalletchanges[wallet1]["txextras"]:
      print("SIGNATURETEST: "+str(verifyingsignature))
      SIGNATUREADDIT = True
      messagething22 = str(wallet1) + str(wallet2) + str(amountofcoins) + str(transactionfee) + str(txextra)
      messagething22 = messagething22.encode('utf-8')
      try:
          verifyingkey.verify(
                base64.b64decode(verifyingsignature),
                messagething22,
                ec.ECDSA(hashes.SHA256())
          )
      except:
          SIGNATUREADDIT = False
      if not SIGNATUREADDIT == False:
                NEWTHING = self.pendingtransactions[wallethash] = {"Type":1,"Sender":wallet1,"Reciever":wallet2,"amountofcoins":amountofcoins,"transactionfee":transactionfee,"txextra":str(txextra),"verifyingsig":verifyingsignature}
      else:
                NEWTHING = self.pendingtransactions[wallethash] = {"Type":1,"Sender":wallet1,"Reciever":wallet2,"amountofcoins":amountofcoins,"transactionfee":transactionfee,"txextra":str(txextra),"verifyingsig":base64.b64encode(verifyingsignature).decode('utf-8')}
      print("SIGNATURE: "+str(NEWTHING["verifyingsig"]))
      self.pendingwalletchanges[wallet1]["Coins"]+=-(amountofcoins+transactionfee)
      

      self.pendingwalletchanges[wallet1]["txextras"][txextra] = {"eeee":"yea"}
      print(txextra)
      return "WE DID IT!"
     else:
         if not self.pendingwalletchanges[wallet1]["Coins"]>=(amountofcoins+transactionfee):
             print("Not enough coins")
         if not amountofcoins>0:
             print("0 coins")
         if not amountofcoins%1==0:
             print("Coins are not an integer")
         if not wallet1 in self.wallets:
             print("wallet1 doesn't exist")
         if not wallet2 in self.wallets:
             print("wallet2 doesn't exist")
         if not transactionfee%1==0:
             print("TRANSACTIONFEE IS NOT AN INTEGER")
         if not transactionfee>0:
             print("TRANSACTIONFEE DOESNT EXIST")
         if  txextra in self.pendingwalletchanges[wallet1]["txextras"]:
             print("TXEXTRA ALREADY IN THERE!!!!")
             print(self.pendingwalletchanges[wallet1]["txextras"])
         if txextra in self.pendingwalletchanges[wallet2]["txextras"]:
             print("TXEXTRA ALREADY IN THERE2!!!!")
         print("MISSING MISSING MISSING")
         return "FAIL"
    def setVCPUS(self,VCPUS):
        self.VCPUS = VCPUS
        print("VCPUS: "+str(VCPUS))
    def getVCPUS(self):
        return self.VCPUS
   
    def getservers(self):
      listthing = {}
      newvalue = 0
      for item in self.serverlist:
          listthing[newvalue]=str(item)
          newvalue+=1
      return listthing
 
    def addnormfile(self,filename,wallet,daysofactivity,filesize,yellowservercoins,verificationsignature):
      if self.transactions[wallet]["Coins"] and yellowservercoins >= PriceperGBperday * daysofactivity*filesize:
            self.files[filename] = {"Wallet": wallet, "DaysOfActivity": daysofactivity, "TimeListed": time.time(), "TimeLeft":daysofactivity*86400}
            self.transactions[wallet]["Coins"] += PriceperGBperday * -1
            self.transactions[wallet]["Coins"] += PriceperGBperday * -1
    def addforcorrectblockcount(self,haash,firstsender,serverip,timecreated,NodesPassedThrough,signature):
      self.proposedblocks = DiskBackedDict("proprosedblocks.db")
      self.nextproposedblocklist = DiskBackedDict("nextproposedblocklist.db")
      publickeything = self.wallets[firstsender]["verifyingkey"]
      print("First Sender: "+str(firstsender))
      try:
          publickeything.verify(
             base64.b64decode(signature),
             firstsender.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
          )
          print("IT WORKED.")
      except Exception as e:
       print("IT FAILED")
       return "This block is invalid."
      if not timecreated<POWERFOREVERLABEL :
       if haash in self.proposedblocks:
        if self.proposedblocks[haash]["SUPERCHECK"] == False:
         if not serverip in self.proposedblocks[haash]["Serversthatgotthisblock"]:



          try:
             with open("gothereok.txt","w") as file:
              file.write("Got here ok")
             newserverblockgetlist = {}

             newserverblockgetlist = dict(self.proposedblocks[haash]["Serversthatgotthisblock"])
             if len(newserverblockgetlist) == 0:
                 lol=True
             sTF = time.time()-self.serverlist[serverip]["timeadded"]

             stuffpower = str(self.blocknum)+str(serverip)
             eothingtoadd2 = hashlib.sha256(stuffpower.encode('utf8')).hexdigest()
             SEALDEAL = int(str(eothingtoadd2),16)
             SEALDEAL = SEALDEAL%7
             numthing = sTF*(SEALDEAL+1)
             newserverblockgetlist[str(serverip)] = {"Server":str(serverip),"Sender":str(firstsender),"Serverwaittime":int(numthing)}


             self.proposedblocks[haash] = {"Blockhash": str(self.proposedblocks[haash]["Blockhash"]),"Count":int(self.proposedblocks[haash]["Count"]) ,"FirstSender":str(self.proposedblocks[haash]["FirstSender"]),"Serversthatgotthisblock":newserverblockgetlist,"Timecreated":self.proposedblocks[haash]["Timecreated"],"Blockdata":self.proposedblocks[haash]["Blockdata"],"Transactionnum":self.proposedblocks[haash]["Transactionnum"],"Timerecieved":self.proposedblocks[haash]["Timerecieved"],"serverwaittime":self.proposedblocks[haash]["serverwaittime"],"BlockDataRecieved":self.proposedblocks[haash]["BlockDataRecieved"],"Dateadded":self.proposedblocks[haash]["Timecreated"],"SUPERCHECK":self.proposedblocks[haash]["SUPERCHECK"],"Signature":signature}
             with open("NewList.txt","w") as file:
                 file.write(str(newserverblockgetlist))
             with open("proposedblockhere.txt","w") as file:
              file.write(str(self.proposedblocks[haash]))
          except Exception as e:
              with open("OBJECTION.txt","w") as file:
                  file.write(str(e))
              lol=True

          return "WE DID IT!"
         else:
             lol=True
        elif haash in self.proposedblocks:
         with open("gothereok.txt","w") as file:
              file.write("Got here ok")
         if self.proposedblocks[haash]["SUPERCHECK"] == True and not haash in self.nextproposedblocklist:
           serverblocklistmust = {}
           serverblocklistmust[str(serverip)] = {"Server":str(serverip),"Sender":firstsender,"Serverwaittime": numthing}

           sTF = time.time()-self.serverlist[str(serverip)]["timeadded"]
           stuffpower = str(self.blocknum)+str(serverip)
           eothingtoadd2 = hashlib.sha256(stuffpower.encode('utf8')).hexdigest()
           SEALDEAL = int(str(eothingtoadd2),16)
           SEALDEAL = SEALDEAL%7
           numthing = sTF*(SEALDEAL+1)
           self.nextproposedblocklist[haash]  = {"Transactionnum":{},"Count":1,"FirstSender":firstsender,"Serverip":serverip, "Blockdata":{},"Serversthatgotthisblock":serverblocklistmust,"Dateadded":time.time(),"Blockhash":"","Timecreated":time.time(),"Timerecieved":time.time(),"serverwaittime":numthing,"BlockDataRecieved":False,"SUPERCHECK":False,"Signature":signature}
           with open("NewList.txt","w") as file:
               file.write(str(serverblocklistmust))
         elif self.proposedblocks[haash]["SUPERCHECK"] == True:
             serverblocklistmust = dict(self.nextproposedblocklist[haash]["Serversthatgotthisblock"])
             serverblocklistmust[str(serverip)] = {"Server":str(serverip),"Sender":self.nextproposedblocklist[haash]["FirstSender"],"Serverwaittime": self.nextproposedblocklist[haash]["serverwaittime"]}
             self.nextproposedblocklist[haash]  = {"Transactionnum":self.nextproposedblocklist[haash]["Transactionnum"],"Count":self.nextproposedblocklist[haash]["Count"],"FirstSender":self.nextproposedblocklist[haash]["FirstSender"],"Serverip":self.nextproposedblocklist[haash]["Serverip"], "Blockdata":self.nextproposedblocklist[haash]["Blockdata"],"Serversthatgotthisblock":serverblocklistmust,"Dateadded":self.nextproposedblocklist[haash]["Dateadded"],"Blockhash":self.nextproposedblocklist[haash]["Blockhash"],"Timecreated":self.nextproposedblocklist[haash]["Timecreated"],"Timerecieved":self.nextproposedblocklist[haash]["Timerecieved"],"serverwaittime":self.nextproposedblocklist[haash]["serverwaittime"],"BlockDataRecieved":self.nextproposedblocklist[haash]["BlockDataRecieved"],"SUPERCHECK":self.nextproposedblocklist[haash]["SUPERCHECK"],"Signature":signature}
             with open("NewList.txt","w") as file:
                 file.write(str(serverblocklistmust))
       else:
          with open("gothereok.txt","w") as file:
              file.write("Got here ok")
          sTF = time.time()-self.serverlist[serverip]["timeadded"]

          stuffpower = str(self.blocknum)+str(serverip)
          eothingtoadd2 = hashlib.sha256(stuffpower.encode('utf8')).hexdigest()
          SEALDEAL = int(str(eothingtoadd2),16)
          SEALDEAL = SEALDEAL%7
          numthing = sTF*(SEALDEAL+1)

          serverlistpowerdevice = {}
          serverlistpowerdevice[str(serverip)] =  {"Server":str(serverip),"Sender":firstsender,"Serverwaittime": numthing}

          self.proposedblocks[haash] = {"Blockhash":str(haash),"Count":1,"FirstSender":firstsender,"Serversthatgotthisblock":dict(serverlistpowerdevice),"Timecreated":timecreated,"Blockdata":{},"Transactionnum":0,"Timerecieved":time.time(),"serverwaittime":numthing,"BlockDataRecieved":False,"Dateadded":time.time(),"SUPERCHECK":False,"Signature":signature}
          with open("proposedblockhere.txt","w") as file:
              file.write(str(self.proposedblocks[haash]))
          with open("NewList.txt","w") as file:
              file.write(str(serverlistpowerdevice))
      else:
          with open("ERRORERRORERROR.txt","w") as file:
              file.write("error....")
          lol=True
    def checkforserverinblock(self,serverip,haash):
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        self.nextproposedblocklist = DiskBackedDict("nextproposedblocklist.db")

        if haash in self.proprosedblocks:
         if serverip in self.proprosedblocks[haash]["Serversthatgotthisblock"]:
          return "YES"
         else:
          return "NO"
        elif haash in self.nextproposedblocklist:
         if serverip in self.nextproposedblocklist[haash]["Serversthatgotthisblock"]:
          return "YES"
         else:
          return "NO"
        else:
            return "NO"
        self.nextproposedblocklist.close()
    def createwallet(self,walletname,verifyingkey):
      walletname = remove_sql(walletname)

      if walletname in self.wallets:
          return "NO."
  
      if not walletname in self.wallets and len(walletname)<21:
        
        self.wallets[walletname] = {"Coins":0,"verifyingkey":load_pem_public_key(verifyingkey, default_backend()),"txextras":{},"verifyingkeysummoningthing":verifyingkey}
 
        self.verifyingkeyspluswallets[self.walletnum] = {"verifyingkey":verifyingkey,"walletname":walletname,"verifyingkeysummoningthing":verifyingkey}

        self.walletnum+=1
        print("WW")
      else:
        return"Wallet already existent"
    def createwalletotherreason(self,walletname,verifyingkey):
       
      walletname = remove_sql(walletname)

      if walletname in self.wallets:
          return "NO."
  
      if not walletname in self.wallets and len(walletname)<21:
        
        self.wallets[walletname] = {"Coins":0,"verifyingkey":load_pem_public_key(verifyingkey, default_backend()),"txextras":{},"verifyingkeysummoningthing":verifyingkey}
 
        self.verifyingkeyspluswallets[self.walletnum] = {"verifyingkey":verifyingkey,"walletname":walletname,"verifyingkeysummoningthing":verifyingkey}
        self.walletnum+=1
        print("WW")
        print("Wallets: "+str(self.wallets))
        return "WE DID IT!!!!!!"
      else:
          print("WE DIDNT!!!!!!")
          return "WE MESSED UP!!!!!!!!!"
   
     
    def gettheavgtransactionfee(self):
       return self.averagetransactionfee
    def getwalletbalance(self,wallet):
        walletbalance = int(self.wallets[wallet]["Coins"])/100000000
        return walletbalance
    def getverificationkey(self,walletname):
        return self.wallets[walletname]["verifyingkeysummoningthing"]
    def getthepriceofuploads(self,filesize,amountofdays):
        return (math.floor(PriceperGBperday*filesize*amountofdays))/(10**8)
    def addblockdatatoblock(self,blockdata,blockhash):
      self.proposedblocks = DiskBackedDict("proprosedblocks.db")
      self.nextproposedblocklist = DiskBackedDict("nextproposedblocklist.db")
      blockstring = ""
      for item in blockdata:
       if blockdata[item]["Type"] == 1:
        blockstring = blockstring+str(blockdata[item]["Sender"])
        blockstring = blockstring+str(blockdata[item]["Reciever"])
        blockstring = blockstring+str(blockdata[item]["amountofcoins"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig"])
        blockstring = blockstring+str(blockdata[item]["txextra"])
       elif blockdata[item]["Type"] == 2:
        blockstring = blockstring+str(blockdata[item]["Sender"])
        blockstring = blockstring+str(blockdata[item]["Reciever"])
        blockstring = blockstring+str(blockdata[item]["transactionfee"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig1"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig2"])
        blockstring = blockstring+str(blockdata[item]["filehash"])
        blockstring = blockstring+str(blockdata[item]["fileprice"])
        blockstring = blockstring+str(blockdata[item]["daysoflasting"])
        blockstring = blockstring+str(blockdata[item]["filesize"])
       elif blockdata[item]["Type"] == 3:
        blockstring = blockstring+str(blockdata[item]["Sender"])
        blockstring = blockstring+str(blockdata[item]["Reciever"])
        blockstring = blockstring+str(blockdata[item]["transactionfee"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig1"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig2"])
        blockstring = blockstring+str(blockdata[item]["filepricething"])
        blockstring = blockstring+str(blockdata[item]["daysoflasting"])
        blockstring = blockstring+str(blockdata[item]["filespace"])
        blockstring = blockstring+str(blockdata[item]["pendingtransactionnum"])
       elif blockdata[item]["Type"] == 4:
        blockstring = blockstring+str(blockdata[item]["Sender"])
        blockstring = blockstring+str(blockdata[item]["Reciever"])
        blockstring = blockstring+str(blockdata[item]["transactionfee"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig1"])
        blockstring = blockstring+str(blockdata[item]["verifyingsig2"])
        blockstring = blockstring+str(blockdata[item]["amountofcoins"])
        blockstring = blockstring+str(blockdata[item]["txextra"])
        blockstring = blockstring+str(blockdata[item]["vmtransactionnum"])
      dashhash = hashlib.sha256(blockstring.encode()).hexdigest()
      if  len(blockdata)<200000 and dashhash == blockhash and blockhash in self.proposedblocks:
        sizeofblock = sys.getsizeof(blockdata)
        self.proposedblocks[blockhash]["Blockdata"] = blockdata
        self.proposedblocks[blockhash]["transactionnum"] = len(blockdata)
        self.proposedblocks[blockhash]["BlockDataRecieved"] = True
        timething = self.proposedblocks[blockhash]["Timecreated"]*sizeofblock
      elif len(blockdata)<200000 and dashhash == blockhash and blockhash in self.nextproposedblocklist:
        sizeofblock = sys.getsizeof(blockdata)
        self.nextproposedblocklist[blockhash]["Blockdata"] = blockdata
        self.nextproposedblocklist[blockhash]["transactionnum"] = len(blockdata)
        self.nextproposedblocklist[blockhash]["BlockDataRecieved"] = True
        timething = self.nextproposedblocklist[blockhash]["Timecreated"]*sizeofblock
      self.proposedblocks.close()
    def getblockamount(self):
        return self.blocknum
    def changewallet(self,wallet):
        self.wallet = wallet
        print(self.wallet)
    def checkforwallet(self,walletname):
        if walletname in self.wallets:
            return "YES"
        else:
            return "NO"
    def getselfwallet(self):
        print(self.wallet)
        return str(self.wallet)
    def checkforblockexistence(self,haash):
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db ")
        if haash in self.proprosedblocks:
            return "YES"
        else:
            return "NO"
    def checkforblockdata(self,haash):
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        if haash in self.proprosedblocks:
            if self.proprosedblocks[haash]["BlockDataRecieved"]==True:
                return "YES"
            else:
                return "NO"
       
    def gettransactionamountofwallet(self,wallet):
        return self.wallets[wallet]["transactionamount"]
  
    
    def getresponsefromthing(self,response,server,typed):
        if server in self.serversallowedtorequestlist and not server in self.requestlist:
            self.requestlist[server+str(self.serverthingpower)] = {"server":server,"time":time.time(),"type":typed,"response":response}
        elif server in self.serversallowedtoaddtorequestlist:
            
            while server+str(self.serverthingpower) in self.requestlist:
                self.serverthingpower+=1
                self.requestlist[server] = {"server":server,"time":time.time(),"type":typed,"response":response}
    def changeserverip(self,serverip):
        self.selfip = serverip
    def getinternetspeedfrom1request(self,serverip):
        thing1 = ""
        thing2 = ""
        adding1 = True
        adding2 = False
        dcount = 0
        for item in self.requestlist:
            if item["server"] == serverip:
                if item["type"] == "InternetSpeed":
                    for letter in item["response"]:
                        if not letter == "u" and adding1 == True:
                            thing1 = thing1+letter
                        elif adding1 == True:
                            adding1 = False
                        elif letter == "d" and adding1 == False and dcount==0:
                            dcount+=1
                        elif letter == "d" and adding1 == False:
                            adding2 == True
                        elif not letter == "u" or "d" and adding2 == True:
                            thing2 = thing2+letter
                        elif adding2 == True:
                            adding2 = False
        return thing1,thing2
    def checkifthinginserverlist(self,serverip):
        serverlist = self.getservers()
        CHECKITQUICK = False
        if str(serverip) in serverlist or str(serverip) in self.specialsuperability:
            return "YES!"
        else:
            for item in serverlist:
                    PRINTTHIS = str(serverlist[item]).find(str(serverip))
                    PRINTTHIS = int(PRINTTHIS)
                    if PRINTTHIS == -1:
                        return "NO!"
                    else:
                        CHECKITQUICK = True
                        break
            if CHECKITQUICK == True:
                return "YES!"
            return "NO!"
    
    def generateavalidationhash(self):
        value = ""
        for item in self.verifyingkeyspluswallets:
            value = value+item["verifyingkey"]+item["walletname"]
        hashthingything = hashlib.sha256(value.encode('utf8')).hexdigest()
        return hashthingything
    def gethashstring(self):
        hashstringhash = hashlib.sha256(self.hashstring.encode('utf8')).hexdigest()
        print("Hashstringlength: "+str(len(hashstringhash)))

        return hashstringhash
    def the600fix(self):
      self.the600thing-=0.25
      with open("changethe600thing.txt","w") as file:
          file.write(str(self.the600thing))
      print("600thing: "+str(self.the600thing))
      return "DID IT"

    def the600get(self):
      return self.the600thing
    def the600reset(self):
       self.the600thing = 600
       return "DID IT"
    def thecountdownfix(self):
      self.thecountdownthing-=0.25
      with open("countdownthing.txt","w") as file:
          file.write(str(self.thecountdownthing))
      return "DID IT"
    def thecountdownget(self):
      return self.thecountdownthing
    def thecountdownreset(self):
      self.thecountdownthing = 3
    def getblocksafterpoint(self,firstblocknum):
        BLOCKDATATYPE = ""
        try:
                dicty = self.blocklist[firstblocknum]["Blockdata"]
                BLOCKDATATYPE = "Blockdata"
        except:
                      print("WRONG TYPE!!!!")
        try:
                      dicty = self.blocklist[firstblocknum]["BlockData"]
                      BLOCKDATATYPE = "BlockData"
        except:
                      print("WRONG TYPE!!!!4")
        self.blocklist = DiskBackedDict("blocklist.db")
        newblocklist = {}
        neoblocknum = int(self.blocknum)
        neoblocknum+=1
        for i in range(neoblocknum-firstblocknum):
            try:
             newblocklist[firstblocknum+i] =         {"BlockData":self.blocklist[firstblocknum+i][BLOCKDATATYPE],"Blockhash":self.blocklist[firstblocknum+i]["Blockhash"],"Dateadded":self.blocklist[firstblocknum+i]["Dateadded"],"FirstSender":self.blocklist[firstblocknum+i]["FirstSender"]}
            except:
                print("IT FAILED!")
        return newblocklist
    def getonespecificblock(self,theblocknum):
        BLOCKDATATYPE = ""
        try:
                dicty = self.blocklist[theblocknum]["Blockdata"]
                BLOCKDATATYPE = "Blockdata"
        except:
                      print("WRONG TYPE!!!!")
        try:
                      dicty = self.blocklist[theblocknum]["BlockData"]
                      BLOCKDATATYPE = "BlockData"
        except:
                      print("WRONG TYPE!!!!4")
        self.blocklist = DiskBackedDict("blocklist.db")
        newblocklist = {}
        neoblocknum = int(self.blocknum)
        neoblocknum+=1
        newblocklist[theblocknum] =         {"BlockData":self.blocklist[theblocknum][BLOCKDATATYPE],"Blockhash":self.blocklist[theblocknum]["Blockhash"],"Dateadded":self.blocklist[theblocknum]["Dateadded"],"FirstSender":self.blocklist[theblocknum]["FirstSender"]}
        return newblocklist[theblocknum]
    def getverifyingchecklist(self):
        DICTIONARY = {}
        for item in self.verifyingkeyspluswallets:
            print("THE ITEM: "+str(item))
            with open("ITEM.txt","w") as file:
                file.write(str(item))
            try:
                key = str(self.verifyingkeyspluswallets[item]["verifyingkey"])
            except Exception as e:
                print("ERROR HERE: "+str(e))
            try:
                wallet = str(self.verifyingkeyspluswallets[item]["walletname"])
            except Exception as e:
                print("ERROR2 HERE: "+str(e))
            DICTIONARY[str(item)] = {"verifyingkey":str(self.verifyingkeyspluswallets[item]["verifyingkeysummoningthing"]),"walletname":str(self.verifyingkeyspluswallets[item]["walletname"])}
        print("DICTIONARY: "+str(DICTIONARY))
        return DICTIONARY
    def getsomeoftheverifyingchecklist(self,beginnum):
        verifyingkeylist = {}
        for i in range(self.walletnum-beginnum):
            verifyingkeylist[i] = self.verifyingkeyspluswallets[beginnum+i]
        return verifyingkeylist
    def getsomeoftheverifyingchecklistalt(self,beginnum,endnum):
        verifyingkeylist = {}
        for i in range(endnum-beginnum):
            verifyingkeylist[i] = self.verifyingkeyspluswallets[beginnum+i]
        return verifyingkeylist
    def getblockamount(self):
        return self.blocknum
    def getkeythingamount(self):
        return len(self.verifyingkeyspluswallets)
    def setverifyingkeyamount(self,keyamount):
        self.walletnum = keyamount
    def setblocknum(self,blocknum):
        self.blocknum = blocknum
    def setblockchain(self,blocklist):
        for item in blocklist.keys():
            BLOCKDATATYPE = ""
            try:
                dicty = blocklist[item]["Blockdata"]
                BLOCKDATATYPE = "Blockdata"
            except:
                      print("WRONG TYPE!!!!")
            try:
                          
                      dicty = blocklist[item]["BlockData"]
                      BLOCKDATATYPE = "BlockData"
            except Exception as e:
                      print("WRONG TYPE!!!!4"+str(e))
            print("ITEM: "+str(item))
            print("BLOCKDATA: "+str(blocklist[item]))
            print("FIRSTSENDER: "+str(blocklist[item]["FirstSender"]))
            FirstSender = str(blocklist[item]["FirstSender"])
            BlockData = str(blocklist[item][BLOCKDATATYPE])
            Blockhash = str(blocklist[item]["Blockhash"])
            Dateadded = str(blocklist[item]["Dateadded"])
            self.blocklist[self.blocknum] = {"BlockData":BlockData,"Blockhash":Blockhash,"Dateadded":Dateadded,"FirstSender":FirstSender}
            self.blocknum+=1
    
    def setserverlist(self,serverlist):
        self.serverlist = serverlist
    def checkforserverthing(self,IP1,IP2):
        if IP1 in self.serverlist:
            if IP2 in  self.serverlist[IP1]:
                return {"IN"}
            else:
                return {"OUT"}
        else:
            return {"OUT"}
    def setthetime(self,time):
        self.blockchainstarttime = time
    def getthetime(self):
        return self.blockchainstarttime
    def setwalletlist(self,walletlist):
        for item in walletlist:
            print("Walletlist: "+str(walletlist))
            if not item in self.wallets:
             print("WALLETLIST ITEM: "+str(walletlist[item]))

             self.wallets[item] = {"verifyingkey":walletlist[item]["verifyingkey"],"Coins":walletlist[item]["Coins"],"txextras":walletlist[item]["txextras"],"verifyingkeysummoningthing":walletlist[item]["Verifyingkeysummoningthing"]}
             self.verifyingkeyspluswallets[item] = {"verifyingkey":walletlist[item]["verifyingkey"],"verifyingkeysummoningthing":walletlist[item]["Verifyingkeysummoningthing"],"walletname":str(item)}
    def getmaxproprosedblock(self):
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        if len(self.proprosedblocks.keys())>0:
         HIGHITEM = max(self.proprosedblocks.keys(), key=lambda x: self.proprosedblocks[x]['serverwaittime'])
         return self.proprosedblocks[HIGHITEM]
        else:
            return "LOLNO!"
    def getransaction(self,itemhash):
        if itemhash in self.pendingtransactions:
            print("DATA: "+str(self.pendingtransactions[itemhash]))
            return "YES"
        else:
            print("IT IS A NO!!!!!!!!!!!!!!!!!!!!")
            return "NO"
    def setverifyingkey(self,verifyingkey):
        self.selfverifyingkey = verifyingkey
    def getverifyingkey(self):
        return self.selfverifyingkey
    def setmaxdrive(self):
        max_drive = max(self.harddrives, key=lambda x: self.harddrives[x]['DataAvailable'])
        return max_drive
    def startfiletransaction(self,filehash,verifyingsig,walletname,filesize,messagetoverifyownership,dayslastingfor,filedata,filename,filetype):
        self.pendingfiletransactionnum += 1
        max_drive = max(self.harddrives, key=lambda x: self.harddrives[x]['DataAvailable'])
        full_path = os.path.join(max_drive, "Wallets")

        if not os.path.exists(full_path):
           os.makedirs(full_path)
        second_path = os.path.join(full_path,str(walletname))
        if not os.path.exists(second_path):
           os.makedirs(second_path)
        second_path = os.path.join(second_path,str(filename))

        dayslastingfor+=-1
        TRUETHINGTHING = False
        transactionnum = self.pendingfiletransactionnum
        verifyingkey = load_pem_public_key(convertthething(self.wallets[walletname]["verifyingkeysummoningthing"]).encode('utf-8'), default_backend())
        try:
            verifyingkey.verify(
              verifyingsig,
              messagetoverifyownership.encode('utf-8'),
              ec.ECDSA(hashes.SHA256())
            )
            TRUETHINGTHING = True
        except:
           lol=True

        if TRUETHINGTHING == True:
         self.pendingfiletransactions[self.pendingfiletransactionnum] = {"txextra":"o","filetype":filetype,"filename":filename,"verifyingsig":"O","fileprice":0,"filehash":filehash,"walletname":walletname,"filesize":filesize,"dayslastingfor":dayslastingfor,"filedata":filedata,"transactionfee":self.averagetransactionfee,"txextra2":"o"}
        else:
            return "500"
        filepricething = (filesize/(10**9)*PriceperGB*dayslastingfor)
        if not walletname in self.pendingwalletchanges:
            self.pendingwalletchanges[walletname] = {
            "Coins": self.wallets[self.wallet]["Coins"],
            "txextras": dict(self.wallets[self.wallet]["txextras"])
            }
        if not self.wallet in self.pendingwalletchanges:
         stringthinghere = ""
         for i in range(10):
             stringthinghere = stringthinghere+letterdict[random.randint(1,35)]
         txextrathing = remove_sql(stringthinghere)
         stringthingtoverify = str(filesize)+str(dayslastingfor)+str(self.wallet)+str(math.floor(filepricething))+str(txextrathing)+str(filehash)+str(math.floor(self.averagetransactionfee))
         signature = self.selfverifyingkey.sign(
             stringthingtoverify.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
            )



         self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra"] = txextrathing
         public_key3333 = self.wallets[self.wallet]["verifyingkey"]
         try:
                         public_key3333.verify(
                          signature,
                          stringthingtoverify.encode('utf-8'),
                          ec.ECDSA(hashes.SHA256())
                         )

         except:
             lol=True
         self.pendingwalletchanges[self.wallet] = {
          "Coins": self.wallets[self.wallet]["Coins"],
          "txextras": dict(self.wallets[self.wallet]["txextras"])
         }
         self.pendingfiletransactions[self.pendingfiletransactionnum]["verifyingsig"] = base64.b64encode(signature).decode('utf-8')
         if filepricething>self.pendingwalletchanges[walletname]["Coins"]:
             return "SORRY WONT WORK, TOO MANY COINS LOL."
         Cando = True
         newkey = ""
         for item in stuffindata:
              if not item == "/":
                  newkey = str(item)

         if Cando == True and filename.find("/") == -1 and filename.find(newkey) == -1:
           with open(second_path,'wb') as file:
             file.write(base64.b64decode(filedata))
         self.files[filename] = {"TypeOfFile":filetype,"STORAGETYPE":2,"walletname":walletname,"filesize":filesize,"filename":second_path}
         self.pendingwalletchanges[walletname]["Coins"]+=-math.floor(filepricething)
         self.pendingfiletransactions[self.pendingfiletransactionnum]["fileprice"] = math.floor(filepricething)
         if walletname not in self.pendingwalletchanges:
          txextrathing = ""

          for i in range(10):
             txextrathing = txextrathing+letterdict[random.randint(1,35)]
          txextrathing = remove_sql(stringthinghere)

          self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra2"] = txextrathing

          stringthingforbuyertoverify = str(filesize)+str("dayslastingfor:")+str(dayslastingfor)+str("fileprice:")+str(math.floor(filepricething))+"transactionamount:"+str(self.pendingfiletransactionnum)+"selfwallet:"+str(self.wallet)+"txextra:"+str(txextrathing)+"transactionfee:"+str(math.floor(self.pendingfiletransactions[self.pendingfiletransactionnum]["transactionfee"]))
          return stringthingforbuyertoverify
        else:
          txextrathing = ""
          for i in range(10):
             txextrathing = txextrathing+letterdict[random.randint(1,35)]
          self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra2"] = txextrathing
          stringthingforbuyertoverify = str(filesize)+str("dayslastingfor:")+str(dayslastingfor)+str("fileprice:")+str(math.floor(filepricething))+"transactionamount:"+str(self.pendingfiletransactionnum)+"selfwallet:"+str(self.wallet)+"txextra:"+str(txextrathing)+"transactionfee:"+str(math.floor(self.pendingfiletransactions[self.pendingfiletransactionnum]["transactionfee"]))
          stringthinghere = ""

          for i in range(10):
             stringthinghere = stringthinghere+letterdict[random.randint(1,35)]
          txextrathing = stringthinghere
          self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra"] = txextrathing
          stringthingtoverify = str(filesize)+str(dayslastingfor)+str(self.wallet)+str(math.floor(filepricething))+str(txextrathing)+str(filehash)+str(math.floor(self.averagetransactionfee))
          signature = self.selfverifyingkey.sign(
             stringthingtoverify.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
            )

          self.pendingwalletchanges[self.wallet]["txextras"][txextrathing] = "Yes"

          self.pendingwalletchanges[walletname]["txextras"][txextrathing] = "Yes"
          self.pendingfiletransactions[self.pendingfiletransactionnum]["fileprice"] = filepricething
          self.pendingfiletransactions[self.pendingfiletransactionnum]["verifyingsig"] = base64.b64encode(signature).decode('utf-8')
          self.pendingwalletchanges[walletname]["Coins"]+=-math.floor(filepricething)
          if filepricething>self.pendingwalletchanges[walletname]["Coins"]:
             return "SORRY WONT WORK, TOO MANY COINS LOL."
          max_drive = max(self.harddrives, key=lambda x: self.harddrives[x]['DataAvailable'])
          Cando = True
          newkey = ""
          for item in stuffindata:
              if not item == "/":
                  newkey = str(item)

          if Cando == True and filename.find("/") == -1 and filename.find(newkey):
           with open(second_path,'wb') as file:
             file.write(base64.b64decode(filedata))
          self.files[filename] = {"TypeOfFile":filetype,"STORAGETYPE":2,"walletname":walletname,"filesize":filesize,"filename":second_path}
          if walletname not in self.pendingwalletchanges:
           self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra2"] = txextrathing
           stringthingforbuyertoverify = str(filesize)+str("dayslastingfor:")+str(dayslastingfor)+str("fileprice:")+str(math.floor(filepricething))+"transactionamount:"+str(self.pendingfiletransactionnum)+"selfwallet:"+str(self.wallet)+"txextra:"+str(txextrathing)+"transactionfee:"+str(math.floor(self.pendingfiletransactions[self.pendingfiletransactionnum]["transactionfee"]))

           return stringthingforbuyertoverify

          else:
           self.pendingfiletransactions[self.pendingfiletransactionnum]["txextra2"] = txextrathing
           stringthingforbuyertoverify = str(filesize)+str("dayslastingfor:")+str(dayslastingfor)+str("fileprice:")+str(math.floor(filepricething))+"transactionamount:"+str(self.pendingfiletransactionnum)+"selfwallet:"+str(self.wallet)+"txextra:"+str(txextrathing)+"transactionfee:"+str(math.floor(self.pendingfiletransactions[self.pendingfiletransactionnum]["transactionfee"]))

           return stringthingforbuyertoverify
    def endthepend(self, walletname, transactionnum, verifyingsig, txextra):
     if txextra == self.pendingfiletransactions[int(transactionnum)]["txextra2"]:
      max_drive = max(self.harddrives, key=lambda x: self.harddrives[x]['DataAvailable'])
      max_drive_space = self.harddrives[max_drive]["DataAvailable"]
      data = {}
      try:
       print(self.pendingfiletransactions[transactionnum])
      except:
          print("HOW???????")
      verifythingy = txextra+str(math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]))+str(self.pendingfiletransactions[transactionnum]["transactionfee"])
      print("VERIFIABLE: "+str(verifythingy))
      print("VERIFYINGSIG1: "+str(self.pendingfiletransactions[transactionnum]["verifyingsig"]))
      try:
                         self.wallets[walletname]["verifyingkey"].verify(
                          verifyingsig,
                          verifythingy.encode('utf-8'),
                          ec.ECDSA(hashes.SHA256())
                         )
                         print("Signature is valid.")
                       
      except Exception as e:
             print("ERROR: "+str(e))
             print("YOU MESSED UP!")
             return "LOL NOO!"
      print("CHECKED")
      if not self.wallet in self.pendingwalletchanges:
            self.pendingwalletchanges[self.wallet] = {"Coins":int(self.wallets[self.wallet]["Coins"]),"txextras":dict(self.wallets[self.wallet]["txextras"])}

      if not walletname in self.pendingwalletchanges and self.wallets[walletname]["Coins"] >= (self.pendingfiletransactions[transactionnum]["fileprice"]+self.pendingfiletransactions[transactionnum]["transactionfee"]) and self.pendingfiletransactions[transactionnum]["filesize"] <= max_drive_space:
            self.pendingwalletchanges[walletname] = {"Coins":int(self.wallets[walletname]["Coins"]),"txextras":dict(self.wallets[walletname]["txextras"])}
            print("CHECKED2")
            hashthis = str(self.pendingfiletransactions[transactionnum]["filehash"])+str(self.pendingfiletransactions[transactionnum]["filesize"])+str(math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]))+str(self.wallet)+str(self.pendingfiletransactions[transactionnum]["dayslastingfor"])+str(self.pendingfiletransactions[transactionnum]["walletname"])
            
            hashthis = hashlib.sha256(hashthis.encode('utf8')).hexdigest()
            self.pendingtransactions[hashthis] = {"txextra":txextra,"Type":2,"Sender":walletname,"Reciever":self.wallet,"filesize":self.pendingfiletransactions[transactionnum]["filesize"],"fileprice":math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]),"daysoflasting":self.pendingfiletransactions[transactionnum]["dayslastingfor"],"filehash":self.pendingfiletransactions[self.pendingfiletransactionnum]["filehash"],"verifyingsig1":base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":(self.pendingfiletransactions[transactionnum]["verifyingsig"]),"transactionfee":math.floor(self.pendingfiletransactions[transactionnum]["transactionfee"]),"txextra2":self.pendingfiletransactions[transactionnum]["txextra2"]}        # Processing the transaction
            print("Pending Transaction: "+str(self.pendingtransactions[hashthis]))
      elif self.pendingwalletchanges[walletname]["Coins"] >=(self.pendingfiletransactions[transactionnum]["fileprice"] + self.pendingfiletransactions[transactionnum]["transactionfee"])and self.pendingfiletransactions[transactionnum]["filesize"] <= max_drive_space:
            print("CHECKED2")
            hashthis = str(self.pendingfiletransactions[transactionnum]["filehash"])+str(self.pendingfiletransactions[transactionnum]["filesize"])+str(math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]))+str(self.wallet)+str(self.pendingfiletransactions[transactionnum]["dayslastingfor"])+str(self.pendingfiletransactions[transactionnum]["walletname"])
            hashthis = hashlib.sha256(hashthis.encode('utf8')).hexdigest()
            data = {"TransactionHash":hashthis}

            self.pendingtransactions[hashthis] = {"txextra":txextra,"Type":2,"Sender":walletname,"Reciever":self.wallet,"filesize":self.pendingfiletransactions[transactionnum]["filesize"],"fileprice":math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]),"daysoflasting":self.pendingfiletransactions[transactionnum]["dayslastingfor"],"filehash":self.pendingfiletransactions[self.pendingfiletransactionnum]["filehash"],"verifyingsig1": base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":self.pendingfiletransactions[transactionnum]["verifyingsig"],"transactionfee":math.floor(self.pendingfiletransactions[transactionnum]["transactionfee"]),"txextra2":self.pendingfiletransactions[transactionnum]["txextra2"]}
            print("Pending Transaction: "+str(self.pendingtransactions[hashthis]))


      else:
        if self.wallets[walletname]["Coins"] < (self.pendingfiletransactions[transactionnum]["fileprice"]+self.pendingfiletransactions[transactionnum]["transactionfee"]):
            print("TOOO MUCH SPENDING!!!!!")
            return "L"
        else:
            print("Not enough space.")
            print("DriveSpace: "+str(max_drive_space))
            return "L"
      servers = self.getservers()
      serverlen = len(servers)
      try:
               try:
                del servers[str(get_local_ip())]
               except:
                   print("Unneccessary")
               if serverlen > 1:
                serverswentthrough = 0
                for servernum1 in range(serverlen):
                 try:
                  thing = requests.post(str(serverthingthing.getprotocol(servers[servernum1])) + servers[servernum1] + "/checkfortransactionexistence", json=data)
                  if thing.status_code == 200:
                   thing = thing.json()
                   thing = thing["Success"]
                   print("THINGDATA:"+str(thing))
                   if thing == "NO":
                    
                    data = {
                        "Sender": walletname,
                        "Reciever": self.wallet,
                        "fileprice": math.floor(self.pendingfiletransactions[transactionnum]["fileprice"]),
                        "transactionfee": math.floor(self.pendingfiletransactions[transactionnum]["transactionfee"]),
                        "verifyingsig1": base64.b64encode(verifyingsig).decode('utf-8'),
                        "txextra": txextra,
                        "verifyingsig2":self.pendingfiletransactions[transactionnum]["verifyingsig"],
                        "filesize":self.pendingfiletransactions[transactionnum]["filesize"],
                        "filehash":self.pendingfiletransactions[transactionnum]["filehash"],
                        "txextra2":self.pendingfiletransactions[transactionnum]["txextra2"],
                        "dayslastingfor":self.pendingfiletransactions[transactionnum]["dayslastingfor"]
                    }
                    try:
                     requests.post(str(serverthingthing.getprotocol(servers[servernum1])) + servers[((servernum1) % serverlen)] + "/addtransactionfromsvronnetwork", json=data)
                    except Exception as e:
                        print("ERROR: "+str(e))
                    print("200")
                    serverswentthrough+=1
                    if serverswentthrough == 5:
                        break
                 except Exception as e:
                    print("BIGERROR: "+str(e))
                    lol=True
      except Exception as e:
              print("ERRORED: "+str(e))
              print("NOOOOOOOOOO!!!!!")
              print(serverlen)
              
      del self.pendingfiletransactions[transactionnum]
      return "W"
     else:
      print("WHAT THE HECK!")
      return "WHAT?"
    def addfiletransactionnotfrommainpc(self,txextra,Sender,Reciever,filesize,fileprice,dayslastingfor,filehash,verifyingsig1,verifyingsig2,transactionfee,txextra2):
    
     if Sender not in self.pendingwalletchanges:
      if len(txextra) == 10 and transactionfee>0 and self.wallets[Sender]["Coins"]>=(transactionfee+fileprice) and not txextra in self.wallets[Sender]["txextras"] and fileprice%1==0:
        truethingthing = False
        CHECKTHING1 = False
        CHECKTHING2 = False
        CHECKTHING3 = False
        CHECKTHING4 = False
        CHECKTHING5 = False
        stringthing1 = str(filesize)+str(dayslastingfor)+Reciever+str(fileprice)+txextra+filehash+str(transactionfee)
        verifyingkey1 = self.wallets[Sender]["verifyingkey"]
        verifyingkey2 = self.wallets[Reciever]["verifyingkey"]
        stringthing2 =       txextra+str(fileprice)+str(transactionfee)+str(".0")
        print("STRINGTHING2: "+str(stringthing2))
        newserverlist = self.getservers()
        serverlen = len(self.serverlist)
        servernumm1 = random.randint(int(min(servers)),int(max(servers)))
        servernumm2 = random.randint(int(min(servers)),int(max(servers)))
        hashdata = {}
        datatosend = {"txextra":txextra,"Sender":Sender,"Reciever":Reciever,"filesize":filesize,"fileprice":fileprice,"dayslastingfor":dayslastingfor,"filehash":filehash,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"transactionfee":transactionfee}
        try:
         verifyingkey2.verify(
          verifyingsig2,
          stringthing1.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
         truethingthing = True
        except:
            print("CRIGNE")
        try:
         verifyingkey1.verify(
          verifyingsig1,
          stringthing2.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
         truethingthing = True
        except:
            print("CRINGE")
        if truethingthing == True:
            hashthis = str(filehash)+str(filesize)+str(fileprice)+str(dayslastingfor)+str(Sender)
            HASHPOWERTHING = hashlib.sha256(hashthis.encode('utf-8')).hexdigest()
            hashdata = {"TransactionHash":HASHPOWERTHING}
            self.pendingwalletchanges[Sender] = {"Coins":self.wallets[Sender]["Coins"]-(transactionfee+fileprice),"txextras":self.wallets[Sender]["txextras"]}
            self.pendingwalletchanges[Sender]["txextras"][txextra] = "YES"
            print("HashData: "+str(hashdata))

            self.pendingwalletchanges[str(self.wallet)] = {"Coins":int(self.wallets[str(self.wallet)]["Coins"]-(transactionfee+fileprice)),"txextras":dict(self.wallets[str(self.wallet)]["txextras"])}
            self.pendingwalletchanges[str(self.wallet)]["txextras"] = "YES"
            self.pendingtransactions[hashthis] = {"txextra":txextra,"Type":2,"Sender":Sender,"Reciever":Reciever,"filesize":filesize,"fileprice":fileprice,"daysoflasting":dayslastingfor,"filehash":filehash,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"txextra2":txextra2,"transactionfee":transactionfee}
        else:
            print("THE SYSTEM HAS FAILED")
            return "EPICFAIL"
        while CHECKTHING1 == False:
            urltopostto = self.getprotocol(newserverlist[servernumm1])+newserverlist[servernumm1]+"/checkfortransactionexistence"
            try:
             responsething = requests.post(urltopostto,hashdata)
             if responsething.status_code == 200:
                datathing = responsething.json()
                datathing = datathing["Success"]
                if datathing == "NO":
                    CHECKTHING1 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm1]
                    serverlen = len(newserverlist)
                if servernumm1 == servernumm2:
                 CHECKTHING1 = False
                 if servernumm1>serverlen-1:
                     servernumm1+=-1
                 else:
                     servernumm1+=1
             else:
                   del newserverlist[servernumm1]
                   servernumm1 = random.randint(int(min(servers)),int(max(servers)))

                   print("HASHDATA: "+str(hashdata))
            except:
                lol=True
            
        while CHECKTHING2 == False:
            urltopostto = self.getprotocol(newserverlist[servernumm2])+newserverlist[servernumm2]+"/checkfortransactionexistence"
            try:
             responsething = requests.post(urltopostto,hashdata)
             if responsething.status_code == 200:
                datathing = responsething.json()
                datathing = datathing["Success"]

                if datathing == "NO":
                    CHECKTHING2 = True
                    del newserverlist[servernumm2]

                    serverlen = len(newserverlist)
                if servernumm1 == servernumm2:
                 CHECKTHING2 = False
                 if servernumm2>serverlen-1:
                     servernumm2+=-1
                 else:
                     servernumm2+=1
             else:
                   del newserverlist[servernumm2]
                   servernumm2 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
            except:
                lol=True
       
        try:
            requests.post(self.getprotocol(newserverlist[servernumm1])+newserverlist[servernumm1]+"/addtransactionfromsvronnetwork",json=datatosend)
            requests.post(self.getprotocol(newserverlist[servernumm2])+newserverlist[servernumm2]+"/addtransactionfromsvronnetwork",json=datatosend)
        except:
            lol=True
        servernumm3 = 0
        servernumm4 = 0
        servernumm5 = 0
        if serverlen>0:
            servernumm3 = random.randint(int(min(servers)),int(max(servers)))
            while CHECKTHING3 == False:
             urltopostto = self.getprotocol(newserverlist[servernumm3])+newserverlist[servernumm3]+"/checkfortransactionexistence"
             try:
              responsething = requests.post(urltopostto,hashdata)
              if responsething.status_code == 200:
                datathing = responsething.json()
                datathing = datathing["Success"]

                if datathing == "NO":
                    CHECKTHING3 = True
                    del newserverlist[servernumm3]

                    serverlen = len(newserverlist)
                if servernumm1 == servernumm2:
                 CHECKTHING3 = False
                 if servernumm2>serverlen-1:
                     servernumm2+=-1
                 else:
                     servernumm2+=1
              else:
                   del newserverlist[servernumm3]
                   servernumm3 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
             except:
                lol=True
            try:
             requests.post(self.getprotocol(newserverlist[servernumm3])+newserverlist[servernumm3]+"/addtransactionfromsvronnetwork",json=datatosend)
            except:
                lol=True
        if serverlen>0:
            servernumm4 = random.randint(int(min(servers)),int(max(servers)))
            while CHECKTHING4 == False:
             urltopostto = self.getprotocol(newserverlist[servernumm4])+newserverlist[servernumm4]+"/checkfortransactionexistence"
             try:
              responsething = requests.post(urltopostto,hashdata)
              if responsething.status_code == 200:
                datathing = responsething.json()
                datathing = datathing["Success"]

                if datathing == "NO":
                    CHECKTHING4 = True
                    del newserverlist[servernumm4]

                    serverlen = len(newserverlist)
                if servernumm1 == servernumm2:
                 CHECKTHING4 = False
                 if servernumm2>serverlen-1:
                     servernumm2+=-1
                 else:
                     servernumm2+=1
              else:
                   del newserverlist[servernumm4]
                   servernumm4 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
             except:
                lol=True
             try:
               requests.post(self.getprotocol(newserverlist[servernumm4])+newserverlist[servernumm4]+"/addtransactionfromsvronnetwork",json=datatosend)
             except:
                lol=True
        if serverlen>0:
            servernumm5 = random.randint(int(min(servers)),int(max(servers)))
            while CHECKTHING5 == False:
             urltopostto = self.getprotocol(newserverlist[servernumm5])+newserverlist[servernumm5]+"/checkfortransactionexistence"
             try:
              responsething = requests.post(urltopostto,hashdata)
              if responsething.status_code == 200:
                datathing = responsething.json()
                datathing = datathing["Success"]

                if datathing == "NO":
                    CHECKTHING5 = True
                    del newserverlist[servernumm5]

                    serverlen = len(newserverlist)
                if servernumm1 == servernumm2:
                 CHECKTHING5 = False
                 if servernumm2>serverlen-1:
                     servernumm2+=-1
                 else:
                     servernumm2+=1
              else:
                   del newserverlist[servernumm5]
                   servernumm5 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
             except:
                lol=True
             try:
              requests.post(self.getprotocol(newserverlist[servernumm5])+newserverlist[servernumm5]+"/addtransactionfromsvronnetwork",json=datatosend)
             except:
                lol=True


     elif len(txextra) == 10 and transactionfee>0 and self.pendingwalletchanges[Sender]["Coins"]>=(transactionfee+fileprice) and not txextra in self.pendingwalletchanges[Sender]["txextras"] :
             truethingthing = False
             CHECKTHING1 = False
             CHECKTHING2 = False
             CHECKTHING3 = False
             CHECKTHING4 = False
             CHECKTHING5 = False
             hashdata = {}

             stringthing1 = str(filesize)+str(dayslastingfor)+Reciever+str(fileprice)+txextra+filehash+str(transactionfee)
             verifyingkey1 = self.wallets[Sender]["verifyingkey"]
             verifyingkey2 = self.wallets[Reciever]["verifyingkey"]
             stringthing2 =       txextra+str(fileprice)+str(transactionfee)+str(".0")
             print("STRINGTHING2: "+str(stringthing2))
             newserverlist = self.getservers()
             serverlen = len(self.serverlist)
             servernumm1 = random.randint(int(min(servers)),int(max(servers)))
             servernumm2 = random.randint(int(min(servers)),int(max(servers)))
             HASHPOWERTHING = ""
             try:
              verifyingkey2.verify(
               verifyingsig2,
               stringthing1.encode('utf-8'),
               ec.ECDSA(hashes.SHA256())

               )
              truethingthing = True
             except:
              truethingthing = False
              print("CRIGNE")
             try:
              verifyingkey1.verify(
               verifyingsig1,
               stringthing2.encode('utf-8'),
               ec.ECDSA(hashes.SHA256())

               )
              truethingthing = True
             except:
              truethingthing = False
              print("CRINGE")
             if truethingthing == True:
              hashthis = str(filehash)+str(filesize)+str(fileprice)+str(dayslastingfor)+str(Sender)
              HASHPOWERTHING = hashlib.sha256(hashthis.encode('utf8')).hexdigest()
              hashdata = {"TransactionHash":HASHPOWERTHING}

              self.pendingwalletchanges[Sender]["Coins"]+=(transactionfee+fileprice)
              self.pendingwalletchanges[Reciever]["Coins"]+=(fileprice)
              self.pendingwalletchanges[Sender]["txextras"][txextra] = "Yes"
              self.pendingwalletchanges[Reciever]["txextras"][txextra] = "Yes"
              print("HashData: "+str(hashdata))
              self.pendingtransactions[hashthis] = {"txextra":txextra,"Type":2,"Sender":Sender,"Reciever":Reciever,"filesize":filesize,"fileprice":fileprice,"daysoflasting":dayslastingfor,"filehash":filehash,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"transactionfee":transactionfee,"txextra2":txextra2}
             responseloop1num = 0
             while CHECKTHING1 == False:
              
              urltopostto = self.getprotocol(newserverlist[servernumm1])+newserverlist[servernumm1]+"/checkfortransactionexistence"
              try:
               if responseloop1num<=10:
                responseloop1num+=1

                responsething = requests.post(urltopostto,hashdata)
                if responsething.status_code == 200:
                 datathing = responsething.json()
                 datathing = datathing["Success"]
                 if datathing == "NO":
                    CHECKTHING1 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm1]
                    serverlen = len(newserverlist)
                 if servernumm1 == servernumm2:
                  CHECKTHING1 = False
                  if servernumm1>serverlen-1:
                     servernumm1+=-1
                  else:
                     servernumm1+=1
                 else:
                    
                   del servers[servernumm2]
                   servernumm2 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
              except:
                  del servers[servernumm1]
                  servernumm1 = random.randint(int(min(servers)),int(max(servers)))

                  lol=True
             responseloop2num = 0 
             while CHECKTHING2 == False:
              urltopostto = self.getprotocol(newserverlist[servernumm2])+newserverlist[servernumm2]+"/checkfortransactionexistence"
              try:
               if responseloop2num <= 10:
                responseloop2num+=1
                responsething = requests.post(urltopostto,hashdata)
               
                if responsething.status_code == 200:
                 datathing = responsething.json()
                 datathing = datathing["Success"]
                 if datathing == "NO":
                    CHECKTHING2 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm2]
                    serverlen = len(newserverlist)
                 if servernumm1 == servernumm2:
                  CHECKTHING2 = False
                  if servernumm2>serverlen-1:
                     servernumm2+=-1
                  else:
                     servernumm2+=1
                else:
                   del servers[servernumm2]
                   servernumm2 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
              except:
                  del servers[servernumm2]
                  servernumm2 = random.randint(int(min(servers)),int(max(servers)))

                  lol=True
             if serverlen>0:
              servernumm3 = random.randint(int(min(servers)),int(max(servers)))

              while CHECKTHING3 == False:
               urltopostto = self.getprotocol(newserverlist[servernumm3])+newserverlist[servernumm3]+"/checkfortransactionexistence"
               try:
                if responseloop2num <= 10:
                 responseloop2num+=1
                 responsething = requests.post(urltopostto,hashdata)
               
                 if responsething.status_code == 200:
                  datathing = responsething.json()
                  datathing = datathing["Success"]
                  if datathing == "NO":
                    CHECKTHING3 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm3]
                    serverlen = len(newserverlist)
                  if servernumm1 == servernumm2:
                   CHECKTHING3 = False
                   if servernumm2>serverlen-1:
                      servernumm2+=-1
                   else:
                     servernumm2+=1
                 else:
                   del servers[servernumm3]
                   servernumm3 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
               except:
                  del servers[servernumm3]
                  servernumm3 = random.randint(int(min(servers)),int(max(servers)))

                  lol=True
               try:
                 requests.post(self.getprotocol(newserverlist[servernumm3])+newserverlist[servernumm3]+"/addtransactionfromsvronnetwork",json=datatosend)
               except:
                 lol=True
             if serverlen>0:
              servernumm4 = random.randint(int(min(servers)),int(max(servers)))

              while CHECKTHING4 == False:
               urltopostto = self.getprotocol(newserverlist[servernumm4])+newserverlist[servernumm4]+"/checkfortransactionexistence"
               try:
                if responseloop2num <= 10:
                 responseloop2num+=1
                 responsething = requests.post(urltopostto,hashdata)
               
                 if responsething.status_code == 200:
                  datathing = responsething.json()
                  datathing = datathing["Success"]
                  if datathing == "NO":
                    CHECKTHING4 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm4]
                    serverlen = len(newserverlist)
                  if servernumm1 == servernumm2:
                   CHECKTHING4 = False
                   if servernumm2>serverlen-1:
                     servernumm2+=-1
                   else:
                     servernumm2+=1
                 else:
                   del servers[servernumm4]
                   servernumm4 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
               except:
                  del servers[servernumm4]
                  servernumm4 = random.randint(int(min(servers)),int(max(servers)))

                  lol=True
               try:
                 requests.post(self.getprotocol(newserverlist[servernumm4])+newserverlist[servernumm4]+"/addtransactionfromsvronnetwork",json=datatosend)
               except:
                 lol=True
             if serverlen>0:
              servernumm5 = random.randint(int(min(servers)),int(max(servers)))

              while CHECKTHING5 == False:
               urltopostto = self.getprotocol(newserverlist[servernumm5])+newserverlist[servernumm5]+"/checkfortransactionexistence"
               try:
                if responseloop2num <= 10:
                 responseloop2num+=1
                 responsething = requests.post(urltopostto,hashdata)
               
                 if responsething.status_code == 200:
                  datathing = responsething.json()
                  datathing = datathing["Success"]
                  if datathing == "NO":
                    CHECKTHING4 = True
                    servernumm1 = random.randint(0,serverlen-1)
                    del newserverlist[servernumm5]
                    serverlen = len(newserverlist)
                  if servernumm1 == servernumm2:
                   CHECKTHING4 = False
                   if servernumm2>serverlen-1:
                     servernumm2+=-1
                   else:
                     servernumm2+=1
                 else:
                   del servers[servernumm5]
                   servernumm5 = random.randint(int(min(servers)),int(max(servers)))
                   print("HASHDATA: "+str(hashdata))
               except:
                  del servers[servernumm5]
                  servernumm5 = random.randint(int(min(servers)),int(max(servers)))

                  lol=True
               try:
                 requests.post(self.getprotocol(newserverlist[servernumm5])+newserverlist[servernumm5]+"/addtransactionfromsvronnetwork",json=datatosend)
               except:
                 lol=True

    def getfile(self,filename,verifyingsig,walletname):
        if self.files[filename]["TypeOfFile"] == "Private" and walletname == self.files[filename]["Walletname"]:
            verifyingkey = self.wallets[walletname]["verifyingkey"]
            tothemoonthing = True
            try:
             verifyingkey.verify(
              verifyingsig,
              filename.encode("utf-8"),
              ec.ECDSA(hashes.SHA256())
             )
            except:
                tothemoonthing = False
            if tothemoonthing == True:
               with open(self.files[filename]["filename"],"rb") as file:
                   data=base64.b64encode(file.read()).decode('utf-8')
                   return data
        elif self.files[filename]["TypeOfFile"] == "Public":
            with open(self.files[filename]["filename"],"rb") as file:
                data=base64.b64encode(file.read()).decode('utf-8')
                return data
    def getridoftransactions(self):
        deletethesekeys = []
        for item in self.pendingfiletransactions:
            deletethesekeys.append(item)
        for item in deletethesekeys:
            del self.pendingfiletransactions[item]
        print("IT's working perfectly fine")
        print("pendingfiletransactions: "+str(self.pendingfiletransactions))
    def addharddrive(self,harddrive):
        self.harddrives[harddrive] = {"DataAvailable":0}
    def setharddrivedata(self,harddrive,dataamount):
       

        self.harddrives[harddrive]["DataAvailable"] = dataamount
    def changeharddrivedata(self,harddrive,dataamount):
        difference = dataamount-self.harddrives[harddrive]["DataAvailable"]
        self.harddrives[harddrive]["DataAvailable"]+=difference
    def buyfilestoragespacep1(self,filespace,verifyingsig,daysoflasting,Sender):
      maxthingy = max(self.harddrives,key=lambda x: self.harddrives[x]['DataAvailable'])
      maxthingyspace = self.harddrives[maxthingy]["DataAvailable"]
      truepowerthing = True
      avgtransactionfee = self.averagetransactionfee
      if filespace<=maxthingyspace:
        verifyingkey = load_pem_public_key(convertthething(self.wallets[Sender]["verifyingkeysummoningthing"]).encode('utf-8'), default_backend())

        verifythisthing = str(filespace)+str(daysoflasting)
        try:
         verifyingkey.verify(
            verifyingsig,
            verifythisthing.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        except:
            truepowerthing = False
            print("LOL")
            return "LOL"
        filepricething = math.floor(((filespace/(10**9))*daysoflasting*PriceperGB))
        stringthingthingthing = ""
        for i in range(10):
            stringthingthingthing = stringthingthingthing+str(letterdict[random.randint(1,35)])
        stringthingthingthing = remove_sql(stringthingthingthing)
        verifythis = str(self.pendingfiletransactionnum)+str(filespace)+str(daysoflasting)+str(Sender)+str(math.floor(filepricething))+str(self.wallet)+stringthingthingthing+str(math.floor(avgtransactionfee))
        signaturething = self.selfverifyingkey.sign(
             verifythis.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
            )
        if truepowerthing == True:
         print("WE DID IT!")
         self.pendingfiletransactions[self.pendingfiletransactionnum] = {"Type":3,"filespace":filespace,"daysoflasting":daysoflasting,"verifyingsig1":"O","verifyingsig2":signaturething,"filepricething":math.floor(filepricething),"Sender":Sender,"txextra":stringthingthingthing,"transactionfee":math.floor(avgtransactionfee),"Reciever":str(self.wallet)}
         sendthisthing = str(self.pendingfiletransactionnum)+"filespace:"+str(filespace)+"daysoflasting:"+str(daysoflasting)+"filepricething:"+str(math.floor(filepricething))+"selfwallet:"+str(self.wallet)+"txextra:"+str(stringthingthingthing)+"transactionfee:"+str(avgtransactionfee)
         self.pendingfiletransactionnum+=1
         return sendthisthing
    def buyfilestoragespacep2(self,pendingtransactionnum,verifyingsig):
     if self.pendingfiletransactions[pendingtransactionnum]["Sender"] not in self.pendingwalletchanges:
      if self.wallets[str(self.pendingfiletransactions[pendingtransactionnum]["Sender"])]["Coins"]>=( self.pendingfiletransactions[pendingtransactionnum]["transactionfee"]+self.pendingfiletransactions[pendingtransactionnum]["filepricething"]):
        verifyingkeythingy = load_pem_public_key(convertthething(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["verifyingkeysummoningthing"]).encode('utf-8'),default_backend())
        verifythis = str(pendingtransactionnum)+str(self.pendingfiletransactions[pendingtransactionnum]["filespace"])+str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"])+str(self.wallet)+str(self.pendingfiletransactions[pendingtransactionnum]["txextra"])+str(self.pendingfiletransactions[pendingtransactionnum]["filepricething"])+str(self.pendingfiletransactions[pendingtransactionnum]["transactionfee"])

        truepowerthing = False
        truethingything1 = False
        truethingything2 = False
        truethingything3 = False
        truethingything4 = False
        truethingything5 = False
        try:
         verifyingkeythingy.verify(
            verifyingsig,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
          )
         truepowerthing = True
        except:
            truepowerthing = False
            print("VERIFYTHISVALUE: "+str(verifythis))
            print("Cringe")
            return "WE MESSED UP!"
            
        if truepowerthing == True:
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Sender"]] = {"Coins":int(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Coins"]),"txextras":dict(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["txextras"])}
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]] = {"Coins":int(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["Coins"]),"txextras":dict(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["txextras"])}
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Coins"]+=-(self.pendingfiletransactions[pendingtransactionnum]["filepricething"]+self.pendingfiletransactions[pendingtransactionnum]["transactionfee"] )
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["txextras"][self.pendingfiletransactions[pendingtransactionnum]["txextra"]] = "Yes"
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["txextras"][self.pendingfiletransactions[pendingtransactionnum]["txextra"]] = "Yes"
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["Coins"]+=(self.pendingfiletransactions[pendingtransactionnum]["filepricething"])
            HASHTHIS = str(pendingtransactionnum)+str(self.pendingfiletransactions[pendingtransactionnum]["filespace"])+str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"])+str(self.wallet)+str(self.pendingfiletransactions[pendingtransactionnum]["txextra"])
            HASHTHIS = hashlib.sha256(HASHTHIS.encode('utf8')).hexdigest()
            HASHTHIS = str(HASHTHIS)
            self.pendingtransactions[HASHTHIS] = {"Type":3,"filespace":str(self.pendingfiletransactions[pendingtransactionnum]["filespace"]),"Sender":self.pendingfiletransactions[pendingtransactionnum]["Sender"],"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"],"daysoflasting":str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"]),"txextra":str(self.pendingfiletransactions[pendingtransactionnum]["txextra"]),"transactionfee":self.pendingfiletransactions[pendingtransactionnum]["transactionfee"],"filepricething":self.pendingfiletransactions[pendingtransactionnum]["filepricething"],"verifyingsig1":base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingfiletransactions[pendingtransactionnum]["verifyingsig2"]).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"]}

            if not self.pendingfiletransactions[pendingtransactionnum]["Sender"] in self.filespacedata:
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]] = {"DataStorageTotal":0,"UsedDataStorage":0,"Transactions":{},"transactionnum":1}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]+=int(self.pendingfiletransactions[pendingtransactionnum]["filespace"])
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Transactions"][self.pendingfiletransactions[pendingtransactionnum]["Sender"]] = {"daysoflasting":self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"],"timestarted":time.time(),"dataspace":self.pendingfiletransactions[pendingtransactionnum]["filespace"]}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]+=1
             print("DATASTORAGETOTAL: "+str(self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]))
     
            else:
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]+=int(self.pendingfiletransactions[pendingtransactionnum]["filespace"])
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Transactions"][self.filespacedata[self.pendingfiletransactionnum[pendingtransactionnum]["Sender"]]["transactionnum"]] = {"daysoflasting":self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"],"timestarted":time.time(),"dataspace":self.pendingfiletransactions[pendingtransactionnum]["filespace"]}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]+=1
             return "Success"

            data = {"filespace":str(self.pendingfiletransactions[pendingtransactionnum]["filespace"]),"daysoflasting":str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"]),"txextra":self.pendingfiletransactions[pendingtransactionnum]["txextra"],"transactionfee":self.pendingfiletransactions[pendingtransactionnum]["transactionfee"],"filepricething":self.pendingfiletransactions[pendingtransactionnum]["filepricething"],"verifyingsig1":base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingfiletransactions[pendingtransactionnum]["verifyingsig2"]).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Sender":self.pendingfiletransactions[pendingtransactionnum]["Sender"],"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"]}
            data2 = {"TransactionHash":HASHTHIS}
            STAYHERE = 0
            servers = self.getservers()
            serverlen = len(servers)
            if serverlen>1:
             while truethingything1 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(0,serverlen-1)
                urlthing = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto]+str("/addfilespacepurchasefromaltPC"))
                urlthing2 = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto]+str("/checkfortransactionexistence"))
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                 
                except Exception as e:
                    print("ERROR: "+str(e))
                    lol=True
                
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                    except:
                        lol=True

                    truethingything1 = True
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
             while truethingything2 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(0,serverlen-1)
                urlthing = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                 if POWERTHING == True:
                  try:
                    responsepawn2 = requests.post(urlthing,json=data)
                    truethingything2 = True
                  except:
                      lol=True
                  
                  
                  STAYHERE = randomservertosendto
                  del servers[randomservertosendto]
                 else:
                  STAYHERE = randomservertosendto
                  del servers[randomservertosendto]
                except Exception as e:
                    print("ERROR: "+str(e))
                    lol=True
            serverlen = len(servers)
            if serverlen>0:
             while truethingything3 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything3 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything3 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything3 = True

                    except:
                        lol=True
                        truethingything3 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything3 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
            serverlen = len(servers)
            if serverlen>0:
             while truethingything4 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything4 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything4 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything4 = True

                    except:
                        lol=True
                        truethingything4 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything4 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
            serverlen = len(servers)
            if serverlen>0:
             while truethingything5 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything5 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything5 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything5 = True

                    except:
                        lol=True
                        truethingything5 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything5 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
              
            print("VERIFYINGKEY: "+str(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["verifyingkey"]))

            del self.pendingfiletransactions[pendingtransactionnum]
          


     else:
      if self.wallets[str(self.pendingfiletransactions[pendingtransactionnum]["Sender"])]["Coins"]>=( self.pendingfiletransactions[pendingtransactionnum]["transactionfee"]+self.pendingfiletransactions[pendingtransactionnum]["filepricething"]):
        verifyingkeythingy = load_pem_public_key(convertthething(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["verifyingkeysummoningthing"]).encode('utf-8'),default_backend())
        verifythis = str(pendingtransactionnum)+str(self.pendingfiletransactions[pendingtransactionnum]["filespace"])+str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"])+str(self.wallet)+str(self.pendingfiletransactions[pendingtransactionnum]["txextra"])+str(self.pendingfiletransactions[pendingtransactionnum]["filepricething"])+str(self.pendingfiletransactions[pendingtransactionnum]["transactionfee"])
        truepowerthing = False
        try:
         verifyingkeythingy.verify(
            verifyingsig,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
          )
         truepowerthing = True
        except:
            truepowerthing = False
            print("VERIFYTHISVALUE: "+str(verifythis))
            print("Cringe")
            return "CRINGE"
        if truepowerthing == True:
            print("STEP0")

            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Coins"]+=-(self.pendingfiletransactions[pendingtransactionnum]["filepricething"]+self.pendingfiletransactions[pendingtransactionnum]["transactionfee"] )
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["txextras"][self.pendingfiletransactions[pendingtransactionnum]["txextra"]]="Yes"
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["txextras"][self.pendingfiletransactions[pendingtransactionnum]["txextra"]] = "Yes"
            self.pendingwalletchanges[self.pendingfiletransactions[pendingtransactionnum]["Reciever"]]["Coins"]+=(self.pendingfiletransactions[pendingtransactionnum]["filepricething"])
            HASHTHIS = str(pendingtransactionnum)+str(self.pendingfiletransactions[pendingtransactionnum]["filespace"])+str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"])+str(self.wallet)+str(self.pendingfiletransactions[pendingtransactionnum]["txextra"])
            HASHTHIS = hashlib.sha256(HASHTHIS.encode('utf8')).hexdigest()
            HASHTHIS = str(HASHTHIS)
            self.pendingtransactions[HASHTHIS] = {"Type":3,"filespace":str(self.pendingfiletransactions[pendingtransactionnum]["filespace"]),"Sender":self.pendingfiletransactions[pendingtransactionnum]["Sender"],"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"],"daysoflasting":str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"]),"txextra":str(self.pendingfiletransactions[pendingtransactionnum]["txextra"]),"transactionfee":self.pendingfiletransactions[pendingtransactionnum]["transactionfee"],"filepricething":self.pendingfiletransactions[pendingtransactionnum]["filepricething"],"verifyingsig1":base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingfiletransactions[pendingtransactionnum]["verifyingsig2"]).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"]}
            truethingything1 = False
            truethingything2 = False
            truethingything3 = False
            truethingything4 = False
            truethingything5 = False
            if not self.pendingfiletransactions[pendingtransactionnum]["Sender"] in self.filespacedata:
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]] = {"DataStorageTotal":0,"UsedDataStorage":0,"Transactions":{},"transactionnum":1}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]+=int(self.pendingfiletransactions[pendingtransactionnum]["filespace"])
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Transactions"][self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]] = {"daysoflasting":self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"],"timestarted":time.time(),"dataspace":self.pendingfiletransactions[pendingtransactionnum]["filespace"]}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]+=1
             print("DATASTORAGETOTAL: "+str(self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]))

            else:
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]+=int(self.pendingfiletransactions[pendingtransactionnum]["filespace"])
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["Transactions"][self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]] = {"daysoflasting":self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"],"timestarted":time.time(),"dataspace":self.pendingfiletransactions[pendingtransactionnum]["filespace"]}
             self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["transactionnum"]+=1
             print("DATASTORAGETOTAL: "+str(self.filespacedata[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["DataStorageTotal"]))
            data = {"filespace":str(self.pendingfiletransactions[pendingtransactionnum]["filespace"]),"daysoflasting":str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"]),"txextra":self.pendingfiletransactions[pendingtransactionnum]["txextra"],"transactionfee":self.pendingfiletransactions[pendingtransactionnum]["transactionfee"],"filepricething":self.pendingfiletransactions[pendingtransactionnum]["filepricething"],"verifyingsig1":base64.b64encode(verifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingfiletransactions[pendingtransactionnum]["verifyingsig2"]).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Sender":self.pendingfiletransactions[pendingtransactionnum]["Sender"],"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"]}
            data2 = {"TransactionHash":HASHTHIS}
            print("STEP02")
            STAYHERE = 0
            servers = self.getservers()

            serverlen = len(self.getservers())
            if serverlen>1:
             print("STEP1")
             while truethingything1 == False:
                print("STEP2")
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto = 0
                try:
                 randomservertosendto =random.randint(0,serverlen-1)
                except:
                    truethingything1 = True
                    truethingything2 = True
                    break
                urlthing = ""
                urlthing2 = ""
                try:
                 urlthing = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = str(self.getprotocol(servers[randomservertosendto])+servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything1 = True
                    truethingything2 = True
                    break
                print("STEP3")

                try:
                 print("THISSTEP4")
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn== "Yes":
                        POWERTHING = False
                 if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                    except:
                       lol=True

                    truethingything1 = True
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
             
                 else:
                     if not serverlen>0:
                        truethingything1 = True
                        truethingything2 = True
                         
                except Exception as e:
                    print("ERROR: "+str(e))
                    print("THATSTEP4")
                    truethingything1 = False
                    truethingything2 = False
                    del servers[randomservertosendto]
                    if not serverlen>0:
                        truethingything1 = True
                        truethingything2 = True
             while truethingything2 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything1 = True
                    truethingything2 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything2 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything2 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything2 = True

                    except:
                        lol=True
                        truethingything2 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything2 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                        truethingything1 = True
                        truethingything2 = True
            serverlen = len(servers)
            if serverlen>0:
             while truethingything3 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything3 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything3 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything3 = True

                    except:
                        lol=True
                        truethingything3 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything3 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
            if serverlen>0:
             while truethingything4 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything4 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything4 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything4 = True

                    except:
                        lol=True
                        truethingything4 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything4 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
            if serverlen>0:
             while truethingything5 == False:
                serverlen = len(servers)
                POWERTHING = True
                try:
                 randomservertosendto =random.randint(min(servers),max(servers))
                except:
                    truethingything3 = True
                    truethingything4 = True
                    truethingything5 = True
                    break
                try:
                 urlthing = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                 urlthing2 = self.getprotocol(servers[randomservertosendto])+str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                except:
                    truethingything5 = True
                    break
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingything5 = False
                    del servers[randomservertosendto]
                    POWERTHING = False
                if POWERTHING == True:
                    try:
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything5 = True

                    except:
                        lol=True
                        truethingything5 = False
                        del servers[randomservertosendto]
                       
                else:
                    truethingything5 = False
                    del servers[randomservertosendto]
                    lol=True
                    if not serverlen>0:
                         truethingything3 = True
                         truethingything4 = True
                         truethingything5 = True
            print("VERIFYINGKEY: "+str(self.wallets[self.pendingfiletransactions[pendingtransactionnum]["Sender"]]["verifyingkey"]))

            del self.pendingfiletransactions[pendingtransactionnum]
    def addfilespacetransactionfromaltPC(self,filespace,daysoflasting,txextra,transactionfee,filepricething,verifyingsig1,verifyingsig2,pendingtransactionnum,Sender,Reciever):
     HASHTHIS = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Reciever)+str(txextra)
     HASHTHIS = hashlib.sha256(HASHTHIS.encode('utf8')).hexdigest()
     if HASHTHIS in self.pendingtransactions:
         print("HASHTHISMEGAFAIL")
         return "L"
     if txextra in self.pendingwalletchanges[Sender]["txextras"]:
         print("TXEXTRAMEGAFAIL")
         return "L"
     if txextra in self.pendingwalletchanges[Reciever]["txextras"]:
         print("TXEXTRAMEGAFAIL")
         return "L"
     if txextra in self.pendingwalletchanges[Sender]["txextras"]:
         print("MESS UP HARD")
         return "MESS UP HARD"
     if txextra in self.pendingwalletchanges[Reciever]["txextras"]:
         print("MESS UP HARD")
         return "MESS UP HARD"
     if Sender not in self.pendingwalletchanges:
      if not Sender in self.pendingwalletchanges:
        coincopy =  dict(self.wallets[Sender]["txextras"])
        self.pendingwalletchanges[Sender] = {"Coins":int(self.wallets[Sender]["Coins"]),"txextras":coincopy}
      if not Reciever in self.pendingwalletchanges:
        coincopy =  dict(self.wallets[Reciever]["txextras"])
        self.pendingwalletchanges[Reciever] = {"Coins":int(self.wallets[Reciever]["Coins"]),"txextras":coincopy}
      if self.wallets[Sender]["Coins"]>=(transactionfee+filepricething) and not txextra in self.wallets[Sender]["txextras"] and not txextra in self.wallets[Reciever]["txextras"] and len(txextra)==10 and transactionfee%1==0 and filepricething%1==0:
        truepowerthing = True
        verifyingkey1 = self.wallets[Sender]["verifyingkey"]
        verifyingkey2 = self.wallets[Reciever]["verifyingkey"]
        verifythis1 = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Reciever)+str(txextra)+str(filepricething)+str(transactionfee)
        truethingythingy3 = False
        truethingythingy4 = False
        POWERTHING = False
        print("VERIFYTHIS1: "+str(verifythis1))

        try:
         verifyingkey1.verify(
           verifyingsig1,
           verifythis1.encode('utf-8'),
           ec.ECDSA(hashes.SHA256())
         )
        except:
            print("ERROR2")

            truepowerthing = False
        verifythis2 = str(self.pendingfiletransactionnum)+str(filespace)+str(daysoflasting)+str(Sender)+str(filepricething)+str(Reciever)+txextra+str(transactionfee)
        print("VERIFYTHIS2: "+str(verifythis2))

        try:
         verifyingkey2.verify(
           verifyingsig2,
           verifythis2.encode('utf-8'),
           ec.ECDSA(hashes.SHA256())
         )
        except Exception as e:
         print("ERROR")
         truepowerthing = False
        if truepowerthing == True:
            HASHTHIS = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Reciever)+str(txextra)
            HASHTHIS = hashlib.sha256(HASHTHIS.encode('utf8')).hexdigest()
            self.pendingwalletchanges[Sender]["Coins"]+=-(filepricething+transactionfee )
            self.pendingwalletchanges[Reciever]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[Sender]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[Reciever]["Coins"]+=(filepricething)
            self.pendingtransactions[HASHTHIS] = {"Type":3,"filespace":filespace,"daysoflasting":daysoflasting,"txextra":txextra,"transactionfee":transactionfee,"filepricething":filepricething,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Sender":Sender,"Reciever":Reciever}
            if txextra in self.pendingwalletchanges[Sender]["txextras"] or txextra in self.pendingwalletchanges[Reciever]["txextras"]:
                print("WE DID IT!, WE DID IT!, WE DID IT!, YAY!")
            if txextra in self.wallets[Sender]["txextras"] or txextra in self.wallets[Reciever]["txextras"]:
                print("OH THATS WHY, OH THATS WHY, OH THATS WHY!")
            data = {"filespace":str(self.pendingfiletransactions[pendingtransactionnum]["filespace"]),"daysoflasting":str(self.pendingfiletransactions[pendingtransactionnum]["daysoflasting"]),"txextra":self.pendingfiletransactions[pendingtransactionnum]["txextra"],"transactionfee":self.pendingfiletransactions[pendingtransactionnum]["transactionfee"],"filepricething":self.pendingfiletransactions[pendingtransactionnum]["filepricething"],"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingfiletransactions[pendingtransactionnum]["verifyingsig2"]).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Sender":self.pendingfiletransactions[pendingtransactionnum]["Sender"],"Reciever":self.pendingfiletransactions[pendingtransactionnum]["Reciever"]}
            data2 = {"TransactionHash":HASHTHIS}
            truethingythingy3 = False
            truethingything4 = False
            truethingything5 = False
            truethingything6 = False
            truethingything7 = False


            while truethingythingy3 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn=responsepawn["Success"]
                    if responsepawn== "NO":
                        POWERTHING = True
                except:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingything3 = False
                
                if POWERTHING == True:
                    try:
                     print("DATA56: "+str(data))

                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingything3 = True
                    except:
                       truethingything3 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
            while truethingythingy4 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy4=False
                if POWERTHING == True:
                    try:
                     print("DATA55: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy4 = True
                     STAYHERE = randomservertosendto
                     del servers[randomservertosendto]
                    except:
                        truethingythingy4 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy4=False
            serverlen = len(servers)
            if serverlen>0:
             while truethingythingy5 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy5=False
                if POWERTHING == True:
                    try:
                     print("DATA55: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy5 = True
                     STAYHERE = randomservertosendto
                     del servers[randomservertosendto]
                    except:
                        truethingythingy5 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy5=False
            serverlen = len(servers)
            if serverlen>0:
             while truethingythingy6 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy6=False
                if POWERTHING == True:
                    try:
                     print("DATA55: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy6 = True
                     STAYHERE = randomservertosendto
                     del servers[randomservertosendto]
                    except:
                        truethingythingy6 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy6=False
            serverlen = len(servers)
            if serverlen>0:
             while truethingythingy7 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy7=False
                if POWERTHING == True:
                    try:
                     print("DATA55: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy7 = True
                     STAYHERE = randomservertosendto
                     del servers[randomservertosendto]
                    except:
                        truethingythingy7 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                    truethingythingy7=False



        else:
            print("Truepowerthing isn't True")
      else:
           if self.wallets[Sender]["Coins"]<(transactionfee+filepricething):
               print("COINERROR")
           if txextra in self.wallets[Sender]["txextras"]:
               print("TXEXTRAERROR")
           if txextra in self.wallets[Reciever]["txextras"]:
               print("TXEXTRAERROR2")
           if not len(txextra) == 10:
               print("TXEXTRAERROR3")
           if not transactionfee%1==0:
               print("TRANSACTIONFEEERROR")
           if not filepricething%1==0:
               print("FILEPRICEERROR")
           return "WE HAVE FAILED"
     else:
       if self.wallets[Sender]["Coins"]>=(transactionfee+filepricething) and not txextra in self.wallets[Sender]["txextras"] and not txextra in self.wallets[Reciever]["txextras"] and len(txextra) == 10 and transactionfee%1==0 and filepricething%1==0:
        truepowerthing = True
        verifyingkey1 = self.wallets[Sender]["verifyingkey"]
        verifyingkey2 = self.wallets[Reciever]["verifyingkey"]
        verifythis1 = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Reciever)+str(txextra)+str(filepricething)+str(transactionfee)
        print("VERIFYTHIS1: "+str(verifythis1))
        try:
         verifyingkey1.verify(
           verifyingsig1,
           verifythis1.encode('utf-8'),
           ec.ECDSA(hashes.SHA256())
         )
        except:
            print("ERROR2")

            truepowerthing = False
        verifythis2 = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Sender)+str(filepricething)+str(Reciever)+str(txextra)+str(transactionfee)
        print("VERIFYTHIS2: "+str(verifythis2))

        try:
         verifyingkey2.verify(
           verifyingsig2,
           verifythis2.encode('utf-8'),
           ec.ECDSA(hashes.SHA256())
         )
        except:
         print("ERROR")
         truepowerthing = False
        if truepowerthing == True:
            HASHTHIS = str(pendingtransactionnum)+str(filespace)+str(daysoflasting)+str(Reciever)+str(txextra)
            HASHTHIS = hashlib.sha256(HASHTHIS.encode('utf8')).hexdigest()
            self.pendingwalletchanges[Sender]["Coins"]+=-(filepricething+transactionfee )
            self.pendingwalletchanges[Reciever]["txextras"][txextra]="YES"
            self.pendingwalletchanges[Sender]["txextras"][txextra]="YES"
            self.pendingwalletchanges[Reciever]["Coins"]+=(filepricething)
            if txextra in self.pendingwalletchanges[Sender]["txextras"] or txextra in self.pendingwalletchanges[Reciever]["txextras"]:
                print("WE DID IT!, WE DID IT!, WE DID IT!, YAY!")
            if txextra in self.wallets[Sender]["txextras"] or txextra in self.wallets[Reciever]["txextras"]:
                print("OH THATS WHY, OH THATS WHY, OH THATS WHY!")
            self.pendingtransactions[HASHTHIS] = {"Type":3,"filespace":filespace,"daysoflasting":daysoflasting,"txextra":txextra,"transactionfee":transactionfee,"filepricething":filepricething,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"pendingtransactionnum":pendingtransactionnum,"Sender":Sender,"Reciever":Reciever}   
            data = {"filespace":str(filespace),"daysoflasting":str(daysoflasting),"txextra":txextra,"transactionfee":transactionfee,"filepricething":filepricething,"verifyingsig1":verifyingsig1,"verifyingsig2":verifyingsig2,"pendingtransactionnum":pendingtransactionnum,"Sender":Sender,"Reciever":Reciever}
            print("DATA: "+str(data))
            data2 = {"TransactionHash":HASHTHIS}
            truethingythingy3 = False
            truethingythingy4 = False
            truethingything5 = False
            truethingything6 = False
            truethingything7 = False
            while truethingythingy3 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:

                 responsepawn = requests.post(urlthing2,json=data2)
                 if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "YES":
                        POWERTHING = False
                except:
                    truethingythingy3 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                if POWERTHING == True:
                    try:
                     print("DATA3: "+str(data))

                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy3 = True

                    except:
                        truethingythingy3 = False
                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy3 = True
                        truethingythingy4 = True
                        print("WE HAVE FAILED!")

                else:
                    truethingythingy4 = False

                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy3 = True
                        truethingythingy4 = True
            while truethingythingy4 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 truethingythingy4 = True

                except Exception as e:
                   print("Error45545: "+str(e))

                   truethingythingy4 = False
                if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "NO":
                        POWERTHING = False
                if POWERTHING == True:
                    try:
                     print("DATA2: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy4 = True
                    
                    except Exception as e:
                        print("Error4554: "+str(e))
                        truethingythingy4 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    truethingythingy4 = False

                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy4 = True
            serverlen = len(servers)
            if serverlen>0:
              while truethingythingy5 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 truethingythingy5 = True

                except Exception as e:
                   print("Error45545: "+str(e))

                   truethingythingy5 = False
                if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "NO":
                        POWERTHING = False
                if POWERTHING == True:
                    try:
                     print("DATA2: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy5 = True
                    
                    except Exception as e:
                        print("Error4554: "+str(e))
                        truethingythingy5 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    truethingythingy5 = False

                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy5 = True
            serverlen = len(servers)
            if serverlen>0:
             while truethingythingy6 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 truethingythingy6 = True

                except Exception as e:
                   print("Error45545: "+str(e))

                   truethingythingy6 = False
                if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "NO":
                        POWERTHING = False
                if POWERTHING == True:
                    try:
                     print("DATA2: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy6 = True
                    
                    except Exception as e:
                        print("Error4554: "+str(e))
                        truethingythingy6 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    truethingythingy6 = False

                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy6 = True
             serverlen = len(servers)
             if serverlen>0:
              while truethingythingy7 == False:
                servers = self.getservers()
                serverlen = len(servers)
                POWERTHING = True
                randomservertosendto =random.randint(min(servers),max(servers))
                urlthing = str(servers[randomservertosendto])+str("/addfilespacepurchasefromaltPC")
                urlthing2 = str(servers[randomservertosendto])+str("/checkfortransactionexistence")
                try:
                 responsepawn = requests.post(urlthing2,json=data2)
                 truethingythingy7 = True

                except Exception as e:
                   print("Error45545: "+str(e))

                   truethingythingy7 = False
                if responsepawn.status_code == 200:
                    responsepawn = responsepawn.json()
                    responsepawn = responsepawn["Success"]
                    if responsepawn == "NO":
                        POWERTHING = False
                if POWERTHING == True:
                    try:
                     print("DATA2: "+str(data))
                     responsepawn2 = requests.post(urlthing,json=data)
                     truethingythingy7 = True
                    
                    except Exception as e:
                        print("Error4554: "+str(e))
                        truethingythingy7 = False
                    STAYHERE = randomservertosendto
                    del servers[randomservertosendto]
                else:
                    truethingythingy7 = False

                    STAYHERE = randomservertosendto
                    try:
                     del servers[randomservertosendto]
                    except:
                        truethingythingy7 = True
       else:
           if self.wallets[Sender]["Coins"]<(transactionfee+filepricething):
               print("COINERROR")
           if txextra in self.wallets[Sender]["txextras"]:
               print("TXEXTRAERROR")
           if txextra in self.wallets[Reciever]["txextras"]:
               print("TXEXTRAERROR2")
           if not len(txextra) == 10:
               print("TXEXTRAERROR3")
           if not transactionfee%1==0:
               print("TRANSACTIONFEEERROR")
           if not filepricething%1==0:
               print("FILEPRICEERROR")
           return "WE HAVE FAILED"
     def addfilealt(self,filedata,filesize,filename,walletname,verifyingsig,filetype):
        maxthingy = max(self.harddrives,key=lambda x: self.harddrives[x]['DataAvailable'])
        maxthingyspace = self.harddrives[maxthingy]["DataAvailable"]
        filename2 = str(maxthingy)+filename

        verifythis = str(filename)+str(walletname)
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        full_path = os.path.join(maxthingy, "Wallets")

        if not os.path.exists(full_path):
           os.makedirs(full_path)
        second_path = os.path.join(full_path,str(walletname))
        if not os.path.exists(second_path):
           os.makedirs(second_path)
        second_path = os.path.join(second_path,str(filename))
        truethis = True
        try:
             verifyingkey.verify(
              verifyingsig,
              verifythis.encode("utf-8"),
              ec.ECDSA(hashes.SHA256())
             )
        except Exception as e:

         truethis = False
        if truethis == True and filesize<=maxthingyspace and not filename in self.files and self.filespacedata[walletname]["DataStorageTotal"]>=filesize and self.filespacedata[walletname]["UsedDataStorage"]<=filesize:
         Cando = True
         newkey = ""
         for item in stuffindata:
              if not item == "/":
                  newkey = str(item)

         if Cando == True and filename.find("/") == -1 and filename.find(newkey) == -1:
            with open(second_path,'wb') as file:
             file.write(base64.b64decode(filedata))


            self.files[filename] = {"filetype":filetype,"STORAGETYPE":2,"walletname":walletname,"filesize":filesize,"filename":second_path}
            self.harddrives[maxthingy]["DataAvailable"]+=-(filesize)
            self.filespacedata[walletname]["UsedDataStorage"]+=-(filesize)
            return "Success."
        else:
            reasons = []
            if not truethis:
             reasons.append("Verification failed.")
            if filesize > maxthingyspace:
             reasons.append("File size exceeds available space.")
            if filename in self.files:
             reasons.append("Filename already exists.")
            if self.filespacedata[walletname]["DataStorageTotal"] < filesize:
             reasons.append("Insufficient storage capacity for wallet.")
            if self.filespacedata[walletname]["UsedDataStorage"] > filesize:
             reasons.append("Exceeds available storage for wallet.")

            return reasons
    def getfilealt(self,walletname,verifyingsig,filename):
      if self.files[filename]["filetype"] == "Private" and walletname == self.files[filename]["walletname"]:
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        verifythis = str(walletname)+str(filename)
        TRUETHAT = True
        try:
         verifyingkey.verify(
            verifyingsig,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except Exception as e:
            TRUETHAT = False
        if TRUETHAT == True:
            with open(self.files[filename]["filename"],"rb") as file:
                sussything = base64.b64encode(file.read()).decode('utf-8')
                return sussything
      else:
          with open(self.files[filename]["filename"],"rb") as file:
              data = base64.b64encode(file.read()).decode('utf-8')
              return data
    def deletefile(self,walletname,verifyingsig,filename):
        verifythisthing = walletname+filename
        verifyingkey = self.wallets[walletname]
        truepowerforever = True
        try:
         verifyingkey.verify(
            verifyingsig,
            verifythisthing.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except:
            truepowerforever = False
        if filename in self.files:
                    lol=True

        else:
            truepowerforever = False
        if truepowerforever == True and walletname == self.files[filename]["walletname"]:
           try:
            os.remove(str(self.files[filename]["filename"]))
           except:
                       lol=True
    def addaspecialblock(self,block):
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        if not "TestBlock" in self.proprosedblocks:
         self.proprosedblocks["TestBlock"] = block
        else:
            del self.proprosedblocks["TestBlock"]
        print(self.proprosedblocks["TestBlock"]["serverwaittime"])
        return "WE KNOW!"
    def editspecialblockwaittime(self):
        block_data = self.proprosedblocks["TestBlock"]
        block_data["serverwaittime"] = 0
        self.proprosedblocks["TestBlock"] = block_data
        self.proprosedblocks.conn.commit()

        self.proprosedblocks["TestBlock"]["serverwaittime"] = 0
        print(self.proprosedblocks["TestBlock"]["serverwaittime"])
    def gothroughfiles(self):
        for item in self.files:
            if item["STORAGETYPE"] == 1:
                todaytime = time.time()
                if not ((item["daysoflasting"]*86400)+item["uploadtime"]) >= todaytime:
                    filename = item["filename"]
                    os.remove("/"+str(filename))
        for item in self.filespacedata:
            for itemm in item["Transactions"]:
                if not ((itemm["daysoflasting"]*86400)+itemm["timecreated"])>=time.time():
                    item["DataStorageTotal"]+=-(itemm["datastorage"])
                    del item["Transactions"][itemm]
        for item in self.files:
            if item["STORAGETYPE"] == 2:
                if self.filespacedata[item["walletname"]["DataStorageTotal"]]<self.filespacedata[item["walletname"]]["UsedDataStorage"]:
                    filename = "/"+self.files[item]["filename"]
                    os.remove(filename)
                    self.filespacedata[item["walletname"]]["UsedDataStorage"]+=-(int(self.files[item]["filesize"]))
    def changeserverfileprice(self,fileprice,server):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            NEWSERVERLIST[item] = {"num":newnum}
            newnum+=1
        self.serverlist[server]["Fileprice"] = fileprice
    def changeservervcpuprice(self,vcpuprice,server):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            NEWSERVERLIST[item] = {"num":newnum}
            newnum+=1
        self.serverlist[server]["VCPUPRICE"] = vcpuprice
    def changeserverRAMGBprice(self,RAMGBPRICE,server):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            NEWSERVERLIST[item] = {"num":newnum}
            newnum+=1
        self.serverlist[server]["RAMGBPRICE"] = RAMGBPRICE
    def changeserverDATATRANSFERGBprice(self,DATATRANSFERGBPRICE,server):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            NEWSERVERLIST[item] = {"num":newnum}
            newnum+=1
        self.serverlist[server]["DATATRANSFERGBPRICE"] = DATATRANSFERGBPRICE
    def getverifyingkeyfromserver(self,server):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            NEWSERVERLIST[item] = {"num":newnum}
            newnum+=1
        return self.serverlist[server]["verifyingkey"]
    def getcheapestCSP(self,bannedservers):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            if not serverlist[item] in bannedservers:
             NEWSERVERLIST[item] = {"num":newnum,"Fileprice":self.serverlist[serverlist[item]]["Fileprice"],"Serverip":self.serverlist[serverlist[item]]["server"]}
             newnum+=1
        highestserverthing = max(NEWSERVERLIST,key=lambda x: NEWSERVERLIST[x]['Fileprice'])
        return NEWSERVERLIST[highestserverthing]["Serverip"]
    def getcheapestCSP2(self,bannedservers):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            if not serverlist[item] in bannedservers:
             NEWSERVERLIST[item] = {"num":newnum,"VCPUPRICE":self.serverlist[serverlist[item]]["VCPUPRICE"],"Serverip":self.serverlist[serverlist[item]]["server"]}
             newnum+=1
        highestserverthing = max(NEWSERVERLIST,key=lambda x: NEWSERVERLIST[x]['VCPUPRICE'])
        return NEWSERVERLIST[highestserverthing]["Serverip"]
    def getcheapestCSP3(self,bannedservers):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            if not serverlist[item] in bannedservers:
             NEWSERVERLIST[item] = {"num":newnum,"RAMGBPRICE":self.serverlist[serverlist[item]]["VCPUPRICE"],"Serverip":self.serverlist[serverlist[item]]["server"]}
             newnum+=1
        highestserverthing = max(NEWSERVERLIST,key=lambda x: NEWSERVERLIST[x]['RAMGBPRICE'])

        return NEWSERVERLIST[highestserverthing]["Serverip"]
    def getcheapestCSP4(self,bannedservers):
        NEWSERVERLIST = {}
        serverlist = self.getservers()
        newnum = 1
        for item in serverlist:
            if not serverlist[item] in bannedservers:
             NEWSERVERLIST[item] = {"num":newnum,"RAMGBPRICE":self.serverlist[serverlist[item]]["VCPUPRICE"],"Serverip":self.serverlist[serverlist[item]]["server"]}
             newnum+=1
        highestserverthing = max(NEWSERVERLIST,key=lambda x: NEWSERVERLIST[x]['RAMGBPRICE'])

        return NEWSERVERLIST[highestserverthing]["Serverip"]
    def addALTserver(self,server):
        self.altserversonthing[server] = {"dateloaded":time.time()}
    def getaltservers(self):
        return self.altserversonthing
    def listfilelistasafile(self):
        
        with open("files.txt","w") as file:
            json.dump(self.files,file)
    def loadfilesintoself(self):
        file_path = "files.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.files = json.load(file)
         print("Dictionary loaded successfully:")
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def listfilespacelistasafile(self):
        
        with open("filespace.txt","w") as file:
            json.dump(self.filespacedata,file)
    def loadfilespaceintoself(self):
        file_path = "filespace.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.filespacedata = json.load(file)
         print("Dictionary loaded successfully:")
         
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def startfilestufftransaction(self,DATATRANSFERGB,DAYSOFLASTING,RAMGB,DATASTORAGEGB,walletname,VCPUS,verifyingsig):
        avgtransactionfee = math.floor(self.averagetransactionfee)
        self.pendingvmtransactions[self.pendingvmnum] = {"DataTransferGB":DATATRANSFERGB,"Daysoflasting":DAYSOFLASTING,"RAMPRICEGB":RAMGB,"DATASTORAGEGB":DATASTORAGEGB,"VCPUS":VCPUS,"Walletname":walletname,"verifyingsig":"O","txextra":"O","Price":0,"verifyingsig1":"O","transactionfee":avgtransactionfee}
        stringthingthingthing = ""
        for i in range(10):
            stringthingthingthing = stringthingthingthing+str(letterdict[random.randint(1,35)])
        stringthingthingthing = remove_sql(stringthingthingthing)
        NEODATATRANSFERGB = DATATRANSFERGB/(10**9)
        NEORAMGB = RAMGB/(10**9)
        NEODATASTORAGEGB = DATASTORAGEGB/(10**9)
        selfkeything = self.selfverifyingkey
        selfwalletthing = self.wallet
        self.pendingvmtransactions[self.pendingvmnum]["txextra"] = stringthingthingthing
        RAMGBPRICE = math.floor(NEORAMGB*RAMPRICEPERGB)
        DATATRANSFERGBPRICE = math.floor(NEODATATRANSFERGB*DATATRANSFERPRICEPERGB)
        VCPUPRICE33 = math.floor(VCPUS*VCPUPRICE)
        DATASTORAGEGB3 = math.floor(NEODATASTORAGEGB*PriceperGB)
        stuff3333 = RAMGBPRICE+DATATRANSFERGBPRICE+VCPUPRICE33+DATASTORAGEGB3
        TRUSTTHING = math.floor(stuff3333*DAYSOFLASTING)
        verifythis4r = str(RAMGB)+str(DATASTORAGEGB)+str(VCPUS)+str(DATATRANSFERGB)+str(walletname)+str(DAYSOFLASTING)

        verifyingkey = self.wallets[walletname]["verifyingkey"]
        verifythis33 = str(RAMGB)+str(DATASTORAGEGB)+str(VCPUS)+str(DATATRANSFERGB)+str(walletname)+str(DAYSOFLASTING)
        TRUETHAT = True
        try:
         verifyingkey.verify(
            verifyingsig,
            verifythis33.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except Exception as e:
            print("ERROR: "+str(e))
            TRUETHAT = False
       
        if self.wallets[walletname]["Coins"]>=TRUSTTHING and TRUETHAT == True:
         self.pendingvmtransactions[self.pendingvmnum]["Price"] = TRUSTTHING
         TRUSTTHING = "Price:"+str(TRUSTTHING)+"walletname:"+walletname+"txextra:"+stringthingthingthing+"pendingvmnum:"+str(self.pendingvmnum)+"selfwallet:"+str(self.wallet)+"transactionfee:"+str(avgtransactionfee)
         signature = selfkeything.sign(
            TRUSTTHING.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
          )
         self.pendingvmtransactions[self.pendingvmnum]["verifyingsig"] = signature
         self.pendingvmnum+=1
         return TRUSTTHING
        else:
         if TRUETHAT == False:
             print("VERIFICATION ERROR.")
         if self.wallets[walletname]["Coins"]<=TRUSTTHING:
             print("Coin error.")
    def endfilestufftransaction(self,newverifyingsig,vmtransactionnum):
        walletname = self.pendingvmtransactions[vmtransactionnum]["Walletname"]
        if not walletname in self.pendingwalletchanges:
           self.pendingwalletchanges[walletname] = {"Coins":self.wallets[walletname]["Coins"],"txextras":dict(self.wallets[walletname]["txextras"])}
           self.pendingwalletchanges[str(self.wallet)] = {"Coins":self.wallets[str(self.wallet)]["Coins"],"txextras":dict(self.wallets[str(self.wallet)]["txextras"])}
        DATATRANSFERPOWER = 0
        with open("datatransferpower.txt","r") as file:
            DATATRANSFERPOWER = int(file.read())
        price = self.pendingvmtransactions[vmtransactionnum]["Price"]
        txextra = self.pendingvmtransactions[vmtransactionnum]["txextra"]
        transactionfee = self.pendingvmtransactions[vmtransactionnum]["transactionfee"]
        verifythis = str(price)+walletname+txextra+str(vmtransactionnum)+str(self.wallet)+str(transactionfee)

        verifyingkey = self.wallets[walletname]["verifyingkey"]
        TRuePOWERforever = True
        VCPUS = self.pendingvmtransactions[vmtransactionnum]["VCPUS"]
        DATASTORAGEGB = self.pendingvmtransactions[vmtransactionnum]["DATASTORAGEGB"]
        DATATRANSFERGB = self.pendingvmtransactions[vmtransactionnum]["DataTransferGB"]
        DAYSOFLASTING = self.pendingvmtransactions[vmtransactionnum]["Daysoflasting"]
        RAMPRICEGB = self.pendingvmtransactions[vmtransactionnum]["RAMPRICEGB"]
        print("VERIFYTHIS: "+str(verifythis))
        try:
         verifyingkey.verify(
            newverifyingsig,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except:
            TRuePOWERforever = False
        if TRuePOWERforever == True and  self.pendingwalletchanges[walletname]["Coins"]>=(price+transactionfee) and not txextra in self.pendingwalletchanges[walletname]["txextras"] and  not txextra in self.pendingwalletchanges[str(self.wallet)]["txextras"] and self.harddrives[VMLOADDRIVE]["DataAvailable"]>=DATASTORAGEGB and self.RAMGB>=RAMPRICEGB and self.VCPUS>=VCPUS:
           hashthis = hashlib.sha256(verifythis.encode('utf-8')).hexdigest()
           self.pendingtransactions[hashthis] = {"Type":4,"amountofcoins":price,"Sender":walletname,"Reciever":str(self.wallet),"transactionfee":transactionfee,"verifyingsig1":base64.b64encode(newverifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingvmtransactions[vmtransactionnum]["verifyingsig"]).decode('utf-8'),"vmtransactionnum":vmtransactionnum,"txextra":txextra}
           print("PENDINGTRANSACTION: "+str(self.pendingtransactions[hashthis]))
           self.pendingwalletchanges[walletname]["Coins"]+=-(transactionfee+price)
           self.pendingwalletchanges[str(self.wallet)]["Coins"]+=price
           self.pendingwalletchanges[walletname]["txextras"][txextra] = "Yes"
           self.pendingwalletchanges[str(self.wallet)]["txextras"][txextra] = "Yes"
           if not walletname in self.vmdatalistalt:
               self.vmdatalistalt[walletname] = {"Transactions":{},"Transactionnum":1,"VCPUS":VCPUS,"DATASTORAGEGB":DATASTORAGEGB,"DATATRANSFERGB":DATATRANSFERGB,"RAMPRICEGB":RAMPRICEGB,"VMNAMES":{},"USEDVCPUS":0,"USEDDATASTORAGEGB":0,"USEDRAMGB":0,"USEDDATATRANSFERGB":0}
               self.vmdatalistalt[walletname]["Transactions"][self.vmdatalistalt[walletname]["Transactionnum"]] = {"VCPUS":VCPUS,"DATASTORAGEGB":DATASTORAGEGB,"DATATRANSFERGB":DATATRANSFERGB,"DAYSOFLASTING":DAYSOFLASTING,"RAMPRICEGB":RAMPRICEGB,"timeuploaded":time.time()}
               self.vmdatalistalt[walletname]["Transactionnum"]+=1
               self.harddrives[VMLOADDRIVE]["DataAvailable"]+=-DATASTORAGEGB
               self.RAMGB+=-RAMPRICEGB
               self.VCPUS+=-VCPUS
               DATATRANSFERPOWER+=-(DATATRANSFERGB*1000)
           else:
               self.vmdatalistalt[walletname]["Transactions"][self.vmdatalistalt[walletname]["Transactionnum"]] = {"VCPUS":VCPUS,"DATASTORAGEGB":DATASTORAGEGB,"DATATRANSFERGB":DATATRANSFERGB,"DAYSOFLASTING":DAYSOFLASTING,"RAMPRICEGB":RAMPRICEGB,"timeuploaded":time.time(),"VMNAMES":{},"USEDVCPUS":0,"USEDDATASTORAGEGB":0,"USEDRAMGB":0,"USEDDATATRANSFERGB":0}
               self.vmdatalistalt[walletname]["Transactionnum"]+=1
               self.vmdatalistalt[walletname]["VCPUS"]+=VCPUS
               self.vmdatalistalt[walletname]["DATASTORAGEGB"]+=DATASTORAGEGB
               self.vmdatalistalt[walletname]["DATATRANSFERGB"]+=DATATRANSFERGB
               self.vmdatalistalt[walletname]["RAMPRICEGB"]+=RAMPRICEGB
               self.harddrives[VMLOADDRIVE]["DataAvailable"]+=-DATASTORAGEGB
               self.RAMGB+=-RAMPRICEGB
               self.VCPUS+=-VCPUS
           serverlist = self.getservers()
           serverlen = len(serverlist)
           servernum1 = random.randint(0,serverlen-1)
           servernum2 = random.randint(0,serverlen-1)
           if servernum1 == servernum2:
               if servernum2+1>=serverlen:
                   servernum2-=1
               else:
                   servernum2+=1

           data = {"Price":price,"txextra":txextra,"transactionfee":transactionfee,"sender":walletname,"vmtransactionnum":vmtransactionnum,"reciever":str(self.wallet),"verifyingsig1":base64.b64encode(newverifyingsig).decode('utf-8'),"verifyingsig2":base64.b64encode(self.pendingvmtransactions[vmtransactionnum]["verifyingsig"]).decode('utf-8')}
           newservernum1 = self.getprotocol(serverlist[servernum1])+serverlist[servernum1]+"/GETTRANSACTIONFROMALTPC"
           newservernum2 = self.getprotocol(serverlist[servernum2])+serverlist[servernum2]+"/GETTRANSACTIONFROMALTPC"
           
           print("W/L?")
           try:                        
                  print("SUCKS")
                  response1 = requests.post(newservernum1,json=data)
                  response2 = requests.post(newservernum2,json=data) 
                  print("RESPONSE1: "+str(response1))
                  print("RESPONSE2: "+str(response1))


           except Exception as e:
               print("ERROR!"+str(e))
               lol=True
           try:
            del serverlist[servernum1]
           except:
               lol=True
           try:
            del serverlist[servernum2]
           except:
               lol=True
           print("W")
           serverlen = len(serverlist)
           if serverlen>0:
            servernum3 = random.randint(min(servers),max(servers))
            newservernum3 = self.getprotocol(serverlist[servernum3])+serverlist[servernum3]+"/GETTRANSACTIONFROMALTPC"

            try:                        
                  print("SUCKS")
                  response1 = requests.post(newservernum3,json=data)
              
                  print("RESPONSE1: "+str(response1))
                  print("RESPONSE2: "+str(response1))


            except Exception as e:
               print("ERROR!"+str(e))
               lol=True
            try:
                del serverlist[servernum3]
            except:
                lol=True
            serverlen =len(serverlist)
           if serverlen>0:
            servernum4 = random.randint(min(servers),max(servers))
            newservernum4 = self.getprotocol(serverlist[servernum4])+serverlist[servernum4]+"/GETTRANSACTIONFROMALTPC"

            try:                        
                  print("SUCKS")
                  response1 = requests.post(newservernum4,json=data)
              
                  print("RESPONSE1: "+str(response1))
                  print("RESPONSE2: "+str(response1))


            except Exception as e:
               print("ERROR!"+str(e))
               lol=True
            try:
                del serverlist[servernum4]
            except:
                lol=True
            serverlen =len(serverlist)
           if serverlen>0:
            servernum5 = random.randint(min(servers),max(servers))
            newservernum5 = self.getprotocol(serverlist[servernum5])+serverlist[servernum5]+"/GETTRANSACTIONFROMALTPC"

            try:                        
                  print("SUCKS")
                  response1 = requests.post(newservernum5,json=data)
              
                  print("RESPONSE1: "+str(response1))
                  print("RESPONSE2: "+str(response1))


            except Exception as e:
               print("ERROR!"+str(e))
               lol=True
            try:
                del serverlist[servernum5]
            except:
                lol=True
            serverlen =len(serverlist)

           return "W"
        else:
            
            failure_reasons = []

# Checking the conditions
            if  TRuePOWERforever==False:
             failure_reasons.append("TruePOWERforever is not True.")

            if self.pendingwalletchanges[walletname]["Coins"] < (price + transactionfee):
             failure_reasons.append("Insufficient coins in the wallet.")

            if txextra in self.pendingwalletchanges[walletname]["txextras"]:
             failure_reasons.append("txextra is already in wallet txextras.")

            if txextra in self.pendingwalletchanges[str(self.wallet)]["txextras"]:
             failure_reasons.append("txextra is in pendingwalletchanges txextras for the current wallet.")

            if self.harddrives[VMLOADDRIVE]["DataAvailable"] < DATASTORAGEGB:
             failure_reasons.append("Insufficient data storage available.")

            if self.RAMGB < RAMPRICEGB:
             failure_reasons.append("Insufficient RAM available.")

            if self.VCPUS < VCPUS:
             failure_reasons.append("Insufficient virtual CPUs available.")

# Print the failure reasons
            if failure_reasons:
             print("The if statement failed for the following reasons:")
            for reason in failure_reasons:
             print(reason)
         
            if len(failure_reasons) == 0:
                print("This is failing, for reasons we do not fully understand.")
            return "WE MESSED UP!"
            

    def getfilestufftransactionfromaltPC(self,price,txextra,transactionfee,sender,vmtransactionnum,reciever,verifyingsig1,verifyingsig2):
        verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)
        verifyingkey = self.wallets[sender]["verifyingkey"]
        verifyingkey222 = self.wallets[reciever]["verifyingkey"]
        truepowerything = True
        try:
         verifyingkey.verify(
            verifyingsig1,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except:
            truepowerything = False
        verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
        try:
         verifyingkey222.verify(
             verifyingsig2,
             verifythis2.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
         )
        except:
            truepowerything = False
        if not sender in self.pendingwalletchanges:
            self.pendingwalletchanges[sender] = {"Coins":int(self.wallets[sender]["Coins"]),"txextras":dict(self.wallets[sender]["txextras"])}
        if not reciever in self.pendingwalletchanges:
            self.pendingwalletchanges[reciever] = {"Coins":int(self.wallets[reciever]["Coins"]),"txextras":dict(self.wallets[reciever]["txextras"])}
        if txextra in self.pendingwalletchanges[sender]["txextras"]:
            return"FAILURE!"
        if txextra in self.pendingwalletchanges[reciever]["txextras"]:
            return"FAILURE!"
        if truepowerything == True and self.pendingwalletchanges[sender]["Coins"]>=(transactionfee+price) and not txextra in self.pendingwalletchanges[sender]["txextras"] and not txextra in self.pendingwalletchanges[reciever]["txextras"]:
            self.pendingwalletchanges[reciever]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[sender]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[sender]["Coins"]+=-(transactionfee+price)
            self.pendingwalletchanges[reciever]["Coins"]+=price
            
            hashthis = str(price)+str(sender)+str(txextra)+str(vmtransactionnum)+str(reciever)+str(transactionfee)
            hashthis = hashlib.sha256(hashthis.encode('utf8')).hexdigest()
            self.pendingtransactions[hashthis] = {"Type":4,"amountofcoins":price,"Sender":sender,"Reciever":reciever,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"vmtransactionnum":vmtransactionnum,"txextra":txextra,"transactionfee":transactionfee}
            data = {"price":price,"txextra":txextra,"transactionfee":transactionfee,"sender":sender,"vmtransactionnum":vmtransactionnum,"reciever":reciever,"verifyingsig1":verifyingsig1,"verifyingsig2":verifyingsig2}
            servers = self.getservers()
            serverlen = len(servers)
            servernum1 = 0
            try:
             servernum1 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                print("ERROR!!!!!")
            try:
             servernum2 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                print("ERROR!!!!!!")
            truepowerthing = True
            truepowerthing2 = True
            truepowerthing3 = True
            truepowerthing4 = True
            truepowerthing5 = True
            checkitthing = "/checkfortransactionexistence"
            while truepowerthing == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum1 = self.getprotocol(servers[servernum1])+str(servers[servernum1])+checkitthing
               try:
                   newresponsething = requests.post(newservernum1,json=checkdata)
                   if newresponsething.status_code == 200:
                    newresponsething = newresponsething.json()                    
                    newresponsething = newresponsething["Success"]
                    if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum1]
                       try:
                        servernum1 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing = False
                           truepowerthing2 = False

                   else:
                       del servers[servernum1]
                       truepowerthing = False

               except:
                   lol=True
               
            while truepowerthing2 == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum2 = self.getprotocol(servers[servernum2])+str(servers[servernum2])+checkitthing
               newresponsething = requests.post(newservernum2,json=checkdata)
               if newresponsething.status_code == 200:
                   newresponsething = newresponsething.json()                    
                   newresponsething = newresponsething["Success"]
                   if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum2]
                       try:
                        servernum2 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing2 = False
                   else:
                       del servers[servernum2]
                       truepowerthing2 = False
           
           
            servernum1Plus = ""
            servernum2Plus = ""
            try:
             servernum1Plus = self.getprotocol(servers[servernum1])+servers[servernum1]+"/GETTRANSACTIONFROMALTPC"
            except:
                lol=True
            try:
             servernum2Plus = self.getprotocol(servers[servernum2])+servers[servernum2]+"/GETTRANSACTIONFROMALTPC"
            except:
                lol=True
            try:
                     response1 = requests.post(servernum1Plus,json=data)
            except:
                lol=True
            try:
                     response2 = requests.post(servernum2Plus,json=data)
            except:
                lol=True
            try:
                del servers[servernum1]
            except:
                lol=True
            try:
                del servers[servernum2]
            except:
                lol=True
            servernum3 = 0
            try:
             servernum3 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                truepowerthing3 = False
                truepowerthing4 = False
                truepowerthing5 = False

                print("ERROR!!!!!!")
            serverlen = len(servers)
            if serverlen>0:
             while truepowerthing3 == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum3 = self.getprotocol(servers[servernum3])+str(servers[servernum3])+checkitthing
               newresponsething = requests.post(newservernum3,json=checkdata)
               if newresponsething.status_code == 200:
                   newresponsething = newresponsething.json()                    
                   newresponsething = newresponsething["Success"]
                   if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum3]
                       try:
                        servernum3 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing3 = False
                   else:
                       del servers[servernum3]
                       truepowerthing3 = False
            try:
                del servers[servernum3]
            except:
                lol=True
            servernum4 = 0
            try:
             servernum4 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                truepowerthing3 = False
                truepowerthing4 = False
                truepowerthing5 = False

                print("ERROR!!!!!!")
            serverlen = len(servers)
            if serverlen>0:
              while truepowerthing4 == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum4 = self.getprotocol(servers[servernum4])+str(servers[servernum4])+checkitthing
               newresponsething = requests.post(newservernum4,json=checkdata)
               if newresponsething.status_code == 200:
                   newresponsething = newresponsething.json()                    
                   newresponsething = newresponsething["Success"]
                   if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum4]
                       try:
                        servernum4 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing4 = False
                   else:
                       del servers[servernum4]
                       truepowerthing4 = False
            try:
                del servers[servernum4]
            except:
                lol=True
            servernum5 = 0
            try:
             servernum5 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                truepowerthing3 = False
                truepowerthing4 = False
                truepowerthing5 = False

                print("ERROR!!!!!!")
            serverlen = len(servers)
            if serverlen>0:
              while truepowerthing5 == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum5 = self.getprotocol(servers[servernum5])+str(servers[servernum5])+checkitthing
               newresponsething = requests.post(newservernum5,json=checkdata)
               if newresponsething.status_code == 200:
                   newresponsething = newresponsething.json()                    
                   newresponsething = newresponsething["Success"]
                   if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum5]
                       try:
                        servernum5 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing5 = False
                   else:
                       del servers[servernum5]
                       truepowerthing5 = False
    def setRAM(self,RAMGB):
        self.RAMGB = RAMGB
    def addatestblock(self):
        self.blocktobesent3 = {}
        self.blocktobesent3[1]={"Type":1,"amountofcoins":100,"verifyingsig":"POOPYHEAD","Sender":"1000","Reciever":"2000","txextra":"TXed"}
        self.proprosedblocks = DiskBackedDict("proprosedblocks.db")
        block_data_copy = copy.deepcopy(self.blocktobesent3)
       
        self.createwallet("2000",public_pem)
        self.createwallet("1000",public_pem)
        goandloadthat = True
        if not 6 in self.proprosedblocks:
          goandloadthat = True
        elif  not "Blockdata" in self.proprosedblocks[6]:
          goandloadthat = True
        else:
         goandloadthat = False
        if goandloadthat == True:
          self.proprosedblocks[6] = {"serverwaittime":99999999999999999999999999999999999,"Blockdata":block_data_copy,"FirstSender":"1000","Dateadded":time.time(),"Blockhash":"ABCDEFG","Serversthatgotthisblock":[]}
          self.proprosedblocks[6]["Serversthatgotthisblock"].append(str(get_local_ip()))
          block_data_copy = copy.deepcopy(self.blocktobesent3)

          self.proprosedblocks[6] =  {"serverwaittime":99999999999999999999999999999999999,"Blockdata":block_data_copy,"FirstSender":"1000","Dateadded":time.time(),"Blockhash":"ABCDEFG","Serversthatgotthisblock":[]}
          if not 1 in self.proprosedblocks[6]["Blockdata"]: 
             print("THAT MAKES NO SENSE!")
             block_data_copy = copy.deepcopy(self.blocktobesent3)

             self.proprosedblocks[6]["Blockdata"] = block_data_copy
        else:
            lol=True
        if not 1 in self.proprosedblocks[6]["Blockdata"]: 
             block_data_copy = copy.deepcopy(self.blocktobesent3)
             self.proprosedblocks[6] = {"serverwaittime":99999999999999999999999999999999999,"Blockdata":block_data_copy,"FirstSender":"1000","Dateadded":time.time(),"Blockhash":"ABCDEFG","Serversthatgotthisblock":[]}
             if len(self.proprosedblocks[6]["Blockdata"]) == 0:
                 print("THAT'S NONSENSE!!!!!!!!!!!!!!!!!!!!")
        return "TXed"
    def getfilestufftransactionfromaltPC(self,price,txextra,transactionfee,sender,vmtransactionnum,reciever,verifyingsig1,verifyingsig2):
        verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)
        verifyingkey = self.wallets[sender]["verifyingkey"]
        verifyingkey222 = self.wallets[reciever]["verifyingkey"]
        truepowerything = True
        try:
         verifyingkey.verify(
            verifyingsig1,
            verifythis.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except:
            truepowerything = False
        verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
        try:
         verifyingkey222.verify(
             verifyingsig2,
             verifythis2.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
         )
        except:
            truepowerything = False
        if not sender in self.pendingwalletchanges:
            self.pendingwalletchanges[sender] = {"Coins":int(self.wallets[sender]["Coins"]),"txextras":dict(self.wallets[sender]["txextras"])}
        if not reciever in self.pendingwalletchanges:
            self.pendingwalletchanges[reciever] = {"Coins":int(self.wallets[reciever]["Coins"]),"txextras":dict(self.wallets[reciever]["txextras"])}
        if txextra in self.pendingwalletchanges[sender]["txextras"]:
            return"FAILURE!"
        if txextra in self.pendingwalletchanges[reciever]["txextras"]:
            return"FAILURE!"
        if truepowerything == True and self.pendingwalletchanges[sender]["Coins"]>=(transactionfee+price) and not txextra in self.pendingwalletchanges[sender]["txextras"] and not txextra in self.pendingwalletchanges[reciever]["txextras"]:
            self.pendingwalletchanges[reciever]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[sender]["txextras"][txextra] = "YES"
            self.pendingwalletchanges[sender]["Coins"]+=-(transactionfee+price)
            self.pendingwalletchanges[reciever]["Coins"]+=price
            
            hashthis = str(price)+str(sender)+str(txextra)+str(vmtransactionnum)+str(reciever)+str(transactionfee)
            hashthis = hashlib.sha256(hashthis.encode('utf8')).hexdigest()
            self.pendingtransactions[hashthis] = {"Type":4,"amountofcoins":price,"Sender":sender,"Reciever":reciever,"verifyingsig1":base64.b64encode(verifyingsig1).decode('utf-8'),"verifyingsig2":base64.b64encode(verifyingsig2).decode('utf-8'),"vmtransactionnum":vmtransactionnum,"txextra":txextra,"transactionfee":transactionfee}
            data = {"price":price,"txextra":txextra,"transactionfee":transactionfee,"sender":sender,"vmtransactionnum":vmtransactionnum,"reciever":reciever,"verifyingsig1":verifyingsig1,"verifyingsig2":verifyingsig2}
            servers = self.getservers()
            serverlen = len(servers)
            servernum1 = 0
            try:
             servernum1 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                print("ERROR!!!!!")
            try:
             servernum2 = random.randint(min(servers),max(servers))
            except:
                truepowerthing1 = False
                truepowerthing2 = False
                print("ERROR!!!!!!")
            truepowerthing = True
            truepowerthing2 = True
            checkitthing = "/checkfortransactionexistence"
            while truepowerthing == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum1 = self.getprotocol(servers[servernum1])+str(servers[servernum1])+checkitthing
               try:
                   newresponsething = requests.post(newservernum1,json=checkdata)
                   if newresponsething.status_code == 200:
                    newresponsething = newresponsething.json()                    
                    newresponsething = newresponsething["Success"]
                    if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum1]
                       try:
                        servernum1 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing = False
                           truepowerthing2 = False

                   else:
                       del servers[servernum1]
                       truepowerthing = False

               except:
                   lol=True
               
            while truepowerthing2 == True:
               checkdata = {"TransactionHash":hashthis}
               newservernum2 = self.getprotocol(servers[servernum2])+str(servers[servernum2])+checkitthing
               newresponsething = requests.post(newservernum2,json=checkdata)
               if newresponsething.status_code == 200:
                   newresponsething = newresponsething.json()                    
                   newresponsething = newresponsething["Success"]
                   if newresponsething == "YES":
                       serverlen+=-1
                       del servers[servernum2]
                       try:
                        servernum2 = random.randint(min(servers),max(servers))
                       except:
                           truepowerthing2 = False
                   else:
                       del servers[servernum2]
                       truepowerthing2 = False
            servernum1Plus = ""
            servernum2Plus = ""
            try:
             servernum1Plus = self.getprotocol(servers[servernum1])+servers[servernum1]+"/GETTRANSACTIONFROMALTPC"
            except:
                lol=True
            try:
             servernum2Plus = self.getprotocol(servers[servernum2])+servers[servernum2]+"/GETTRANSACTIONFROMALTPC"
            except:
                lol=True
            try:
                     response1 = requests.post(servernum1Plus,json=data)
            except:
                lol=True
            try:
                     response2 = requests.post(servernum2Plus,json=data)
            except:
                lol=True
    def removethesillytransactions(self):
        deletetheseplease = {}

        for item in self.vmdatalistalt:
            for itemm in self.vmdatalistalt[item]["Transactions"]:
                daysoflasting = self.vmdatalistalt[item]["Transactions"][itemm]["DAYSOFLASTING"]
                timeuploaded = self.vmdatalistalt[item]["Transactions"][itemm]["timeuploaded"]
                secondsoflasting = daysoflasting*86400
                endtime = timeuploaded+secondsoflasting
                realtime = time.time()
                if endtime<=realtime:
                    self.vmdatalistalt[item]["VCPUS"]+=-self.vmdatalistalt[item]["Transactions"][itemm]["VCPUS"]
                    self.vmdatalistalt[item]["RAMPRICEGB"]+=-self.vmdatalistalt[item]["Transactions"][itemm]["RAMPRICEGB"]
                    self.vmdatalistalt[item]["DATASTORAGEGB"]+=-self.vmdatalistalt[item]["Transactions"][itemm]["DATASTORAGEGB"]
                    self.vmdatalistalt[item]["DATATRANSFERGB"]+=-self.vmdatalistalt[item]["Transactions"][itemm]["DATATRANSFERGB"]
                    self.harddrives[VMLOADDRIVE]["DataAvailable"]+=self.vmdatalistalt[item]["Transactions"][itemm]["DATASTORAGEGB"]
                    self.VCPUS+=self.vmdatalistalt[item]["Transactions"][itemm]["VCPUS"]
                    self.RAMGB+=self.vmdatalistalt[item]["Transactions"][itemm]["RAMPRICEGB"]
                    deletetheseplease[itemm] = item
                    print("WE DID IT !")
        for item in deletetheseplease:
         del self.vmdatalistalt[item]["Transactions"][deletetheseplease[item]]
    def vmstufflistlistasafile(self):
         with open("vmstufflist.txt","w") as file:
            json.dump(self.vmdatalistalt,file)
    def loadvmstufflistintoself(self):
        file_path = "vmstufflist.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.vmdatalistalt = json.load(file)
         print("Dictionary loaded successfully:")
         
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def getharddrivestorage(self):
        selfdatastorage = 0
        for item in self.harddrives:
            selfdatastorage+=item["DataAvailable"]
        return selfdatastorage
    def getRAMonSERVER(self):
        return self.RAMGB
    def CREATEVMLOL(self,VCPUS,DATATRANSFERMB,RAMMB,DATASTORAGEMB,verifyingsig1,walletname):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        THINGSTRING = str(VCPUS)+str(DATATRANSFERMB)+str(RAMMB)+str(DATASTORAGEMB)
        TRUEPOWER = True
        try:
         verifyingkey.verify(
            verifyingsig1,
            THINGSTRING.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
        except:
            TRUEPOWER = False
        if walletname in self.vmdatalistalt and TRUEPOWER == True and VCPUS>=1 and RAMMB>=1800 and DATASTORAGEMB>=10000 and (self.vmdatalistalt[walletname]["VCPUS"]>=VCPUS-self.vmdatalistalt[walletname]["USEDVCPUS"]) and self.vmdatalistalt[walletname]["DATASTORAGEGB"]>=(DATASTORAGEMB/1000) and self.vmdatalistalt[walletname]["DATATRANSFERGB"]>=(DATATRANSFERMB/1000) and (self.vmdatalistalt[walletname]["RAMPRICEGB"]-self.vmdatalistalt[walletname]["USEDRAMGB"])>=(RAMMB/1000)  and (DATASTORAGEMB/1000)<=(self.vmdatalistalt[walletname]["DATASTORAGEGB"]-self.vmdatalistalt[walletname]["USEDDATASTORAGEGB"])  and (DATATRANSFERMB/1000)<=(self.vmdatalistalt[walletname]["DATATRANSFERGB"]-self.vmdatalistalt[walletname]["USEDDATATRANSFERGB"]) and not selfnum in listofkeyeys and RAMMB<=self.RAMGB and DATASTORAGEMB<=self.harddrives[VMLOADDRIVE]["DataAvailable"] and DATATRANSFERMB<=DATATRANSFERPOWER:
         vmnamething =vm_name+str(selfnum)
         self.truevmdatalist[vmnamething] = {"VCPUS":VCPUS,"DATATRANSFERGB":DATATRANSFERMB*1024,"RAMPRICEGB":RAMMB*1024,"DATASTORAGEGB":DATASTORAGEMB*1024,"USEDVCPUS":0,"USEDDATATRANSFERGB":0,"USEDRAMGB":0,"USEDDATASTORAGEGB":0}
         self.vmdatalistalt[walletname]["VMNAMES"][vmnamething] ={"RAMMB":RAMMB,"DATASTORAGEMB":DATASTORAGEMB,"DATATRANSFERMB":DATATRANSFERMB,"VCPUS":VCPUS,"timeuploaded":time.time(),"timeoflastcheck":time.time(),"Active":True,"InternetSpeedUsed":0}
         self.vmdatalistalt[walletname]["USEDVCPUS"]+=VCPUS
         self.vmdatalistalt[walletname]["USEDDATASTORAGEGB"]+=(DATASTORAGEMB/1024)
         self.vmdatalistalt[walletname]["USEDRAMGB"]+=(RAMMB/1024)
         self.vmdatalistalt[walletname]["USEDDATATRANSFERGB"]+=(DATATRANSFERMB/1024)
         

         try:
          clone_vm(vm_name,vmnamething,RAMMB,DATASTORAGEMB,VCPUS)
         except:
             print("ERROR")
         try:
          start_virtual_machine(vm_name)
          time.sleep(0.01)

          # Simulate pressing the Enter key
          pyautogui.press('enter')
          time.sleep(2)
          stop_virtual_machine(vm_name)
          return vmnamething
         except:
             print("ERROR")
         return vm_name
        else:
            if TRUEPOWER == False:
                print("The verification failed.")
            if  VCPUS<=1:
                print("Not enough VCPUS")
            if RAMMB<=8192:
                print("Not enough RAM")
            if DATASTORAGEMB<=50000:
                print("Not enough Data storage")
            if (self.vmdatalistalt[walletname]["VCPUS"]>=VCPUS-self.vmdatalistalt[walletname]["USEDVCPUS"]):
                print("Not enough VCPUS in your wallet.")
            if self.vmdatalistalt[walletname]["DATASTORAGEGB"]<=(DATASTORAGEMB/1000):
                print("Not enough Datastorage in your wallet")
            if self.vmdatalistalt[walletname]["DATATRANSFERGB"]<=(DATATRANSFERMB/1000):
                print("Not enough datatransfer gigabytes in your wallet.")
            if (self.vmdatalistalt[walletname]["RAMPRICEGB"]-self.vmdatalistalt[walletname]["USEDRAMGB"])<=(RAMMB/1000):
                print("Not Enough RAMGB in your wallet.")
            if (DATASTORAGEMB/1000)>=(self.vmdatalistalt[walletname]["DATASTORAGEGB"]-self.vmdatalistalt[walletname]["USEDDATASTORAGEGB"]):
                print("Not enough datastorage in your wallet.#2")
            if (DATATRANSFERMB/1000)>=(self.vmdatalistalt[walletname]["DATATRANSFERGB"]-self.vmdatalistalt[walletname]["USEDDATATRANSFERGB"]):
                print("DATATRANSFER IN WALLET IS TOO LOW. PRoblem detected.")
            if selfnum in listofkeyeys:
                print("BIG selfnum error.")
            if RAMMB>=self.RAMGB:
                print("Not enough ram in this computer #2")
            if DATASTORAGEMB>=self.harddrives[VMLOADDRIVE]["DataAvailable"]:
                print("NOT ENOUGH DATA STORAGE IN THIS COMPUTER!")
            if DATATRANSFERMB>=DATATRANSFERPOWER:
                print("NOT ENOUGH DATATRANSFER MEGABYTES IN THIS COMPUTER!")
            if walletname not in self.vmdatalistalt:
                print("WALLETNAME NOT IN THE RIGHT VMDATALIST!")
            return "W"
    def GOTHROUGHVMS(self):
        deletetheseplease = {}
       
        for item in self.vmdatalistalt:
         if len(self.vmdatalistalt[item]["VMNAMES"])>0:
          for itemm in self.vmdatalistalt[item]["VMNAMES"]:
            if self.truevmdatalist[itemm]["RAMPRICEGB"]<self.truevmdatalist[itemm]["USEDRAMGB"] or self.truevmdatalist[itemm]["DATASTORAGEGB"]<self.truevmdatalist[itemm]["USEDDATASTORAGEGB"] or self.truevmdatalist[itemm]["DATATRANSFERGB"]<self.truevmdatalist[itemm]["USEDDATATRANSFERGB"] or self.truevmdatalist[itemm]["VCPUS"]<self.truevmdatalist[item]["USEDVCPUS"]:
                delete_virtual_machine(str(itemm))
                self.vmdatalistalt[item]["USEDDATASTORAGEGB"]+=-(self.truevmdatalist[itemm]["DATASTORAGEGB"]/1000)
                self.vmdatalistalt[item]["USEDDATATRANSFERGB"]+=-(self.truevmdatalist[itemm]["DATATRANSFERGB"]/1000)
                deletetheseplease[item] = itemm
                print("WE DID IT, WE DID IT, WE DID IT, YEAH!")
        for item in deletetheseplease:
         del self.vmdatalistalt[item]["VMNAMES"][deletetheseplease[item]]  
    def startVM(self,walletname,verifyingsig,vmname):
       
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and vmname in self.vmdatalistalt[walletname]["VMNAMES"]:
            start_virtual_machine(vmname)
            time.sleep(0.01)

            # Simulate pressing the Enter key
            pyautogui.press('enter')
    def ADDINTERNETSPEEDTRANSFERDATATOVM(self,walletname,verifyingsig,vmname,datatransferstuff):
       
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and self.vmdatalistalt[walletname]["DATATRANSFERGB"]>=datatransferstuff/(10**3) and self.vmdatalistalt[walletname]["USEDDATATRANSFERGB"]<=self.vmdatalistalt[walletname]["DATATRANSFERGB"]+datatransferstuff/(10**3) and DATATRANSFERPOWER>datatransferstuff:
                        self.truevmdatalist[vmname]["DATATRANSFERMB"]+=datatransferstuff
                        self.vmdatalistalt[walletname]["DATATRANSFERGB"]+=(datatransferstuff/(10**3))
                        DATATRANSFERSTUFF+=-(datatransferstuff)
    def ADDVMSTORAGE(self,walletname,verifyingsig,vmname,VMSTORAGE):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and self.vmdatalistalt[walletname]["DATASTORAGEGB"]>=VMSTORAGE/(10**3) and self.vmdatalistalt[walletname]["USEDSTORAGEGB"]<=self.vmdatalistalt[walletname]["DATASTORAGEGB"]+VMSTORAGE/(10**3) and VMSTORAGE<=self.harddrives[VMLOADDRIVE]["DataAvailable"]/(10**6):
                        self.truevmdatalist[vmname]["DATASTORAGEMB"]+=VMSTORAGE
                        self.vmdatalistalt[walletname]["DATASTORAGEGB"]+=(VMSTORAGE/(10**3))

                        modify_vm_storage(vmname,VMSTORAGE)
    def ADDRAMTOVM(self,walletname,verifyingsig,vmname,VMSTORAGE):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and self.vmdatalistalt[walletname]["RAMPRICEGB"]>=VMSTORAGE/(10**3) and self.vmdatalistalt[walletname]["USEDRAMGB"]<=self.vmdatalistalt[walletname]["RAMPRICEGB"]+VMSTORAGE/(10**3) and VMSTORAGE<=(self.RAMGB/(10**6)):
                        self.truevmdatalist[vmname]["RAMMB"]+=VMSTORAGE
                        self.vmdatalistalt[walletname]["USEDRAMGB"]+=(VMSTORAGE/(10**3))
                        self.RAMGB+=-(VMSTORAGE*(10**6))
                        modify_vm_storage(vmname,VMSTORAGE)
    def DELETEVM(self,walletname,verifyingsig,vmname):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and vmname in self.vmdatalistalt[walletname]["VMNAMES"]:
            delete_virtual_machine(vmname)
    def ADDFILETOVM(self,walletname,filename,vmname,verifyingsig):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        truepower2 = True
        validatethis = vmname+str(filename)
        filedata = ""
        try:
         verifyingkey.verify(
          verifyingsig,
          validatethis.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True and vmname in self.vmdatalistalt[walletname]["VMNAMES"] and filename in self.files:
           try:
               with open(filename,"r") as file:
                   filedata = str(file.read())
           except:
                truepower2 = False
           if truepower2 == True:
            try:
             add_file_to_vm(vm_name,filename,filedata,walletname)
            except:
                print("ERROR")
    def setdoomblocks(self,doomblocks):
        print("DOOMBLOCKS: "+str(doomblocks))
        self.blocksuntildoom = doomblocks
    def setblockreward(self,blockreward):
        print("BLOCKREWARD: "+str(blockreward))

        self.blockreward = blockreward
    def ADDFILETOVM2(self,walletname,filename,filedata,vmname,verifyingsig):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        truepower2 = True
        validatethis = vmname+str(filename)
        filedata = ""
        try:
         verifyingkey.verify(
          verifyingsig,
          validatethis.encode('utf-8'),
          ec.ECDSA(hashes.SHA256()) 
         )

        except:
         truepower = False
        if truepower == True and vmname in self.vmdatalistalt[walletname]["VMNAMES"]:
           try:
            add_file_to_vm(vm_name,filename,filedata)
           except:
               print("Error")
    def CHECKTHINGSINTERNETSPEEDVALIDITY(self,vmname,internetspeed):
        walletname = VMDATALIST[vmname]["WalletName"]
        if self.vmdatalistalt[walletname]["VMNAMES"][vmname]["DATATRANSFERMB"]<(internetspeed*(10**6)):
            self.vmdatalistalt[walletname]["VMNAMES"][vmname]["timeoflastcheck"] = time.time()
            self.vmdatalistalt[walletname]["VMNAMES"][vmname]["Active"] = False
            self.vmdatalistalt[walletname]["VMNAMES"][vmname]["InternetSpeedUsed"]= internetspeed
            stop_virtual_machine(vm_name)
        self.vmdatalistalt[walletname]["VMNAMES"]["timeoflastcheck"] = time.time()

    def STOPVM(self,vmname,walletname,verifyingsig):
     
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
            verifyingsig,
            vmname.encode('utf-8'),
            ec.ECDSA(hashes.SHA256()) 
         )
        except:
            truepower = False
        if truepower == True:
          try:
            stop_virtual_machine(vmname)
          except:
              print("Error")
    def executecommandonVM(self,vmname,verifyingsig,command):
        walletname = VMDATALIST[vmname]["WalletName"]
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        message = vmname+str(command)
        truepower = True
        try:
            verifyingkey.verify(
                verifyingsig,
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256()) 
            )
        except:
            truepower = False
        if truepower == True:
          try:
            addcommands(vmname,command)
          except:
              print("Error")
    def checkVMTHINGYTIMEY(self,vmname):
        walletname = VMDATALIST[vmname]["WalletName"]
        timelast = self.vmdatalistalt[walletname]["VMNAMES"][vmname]["timeoflastcheck"]
        neotimelast = time.time()-timelast
        if neotimelast>200 and self.vmdatalistalt[walletname]["VMNAMES"][vmname]["Active"] == True:

            try:
                delete_virtual_machine(vmname)
            except:
                print("Error")
    def LISTVMDATALISTASFILE(self):
        with open("vmdatalist1.txt","w") as file:
            json.dump(VMDATALIST,file)
    def LISTVMDATALIST2ASFILE(self):
         with open("vmdatalist2.txt","w") as file:
            json.dump(VMDATALIST2,file)
    def LISTKEYEYESASFILE(self):
         with open("listofkeyeys.txt","w") as file:
             json.dump(listofkeyeys,file)
    def loadvmdatalistintoself(self):
        file_path = "vmdatalist1.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          VMDATALIST = json.load(file)
         print("Dictionary loaded successfully:")
         
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def loadvmdatalist2intoself(self):
        file_path = "vmdatalist2.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          VMDATALIST2 = json.load(file)
         print("Dictionary loaded successfully:")
         
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def loadlistofkeyeysintoself(self):
        file_path = "listofkeyeys.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          listofkeyeys = json.load(file)
         print("Dictionary loaded successfully:")
         
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def getfilespaceamount(self,walletname,verifyingsig):
        truepower = True
        try:
         self.wallets[walletname]["verifyingkey"].verify(
          verifyingsig,
          walletname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
        except:
            truepower = False
            print("WE MESSED UP")
        if truepower == True:
            return self.filespacedata[walletname]["DataStorageTotal"]
    def verifywhatever(self,walletname,verifyingsig):
        truepower = True
        try:
         self.wallets[walletname]["verifyingkey"].verify(
          verifyingsig,
          walletname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
        except:
            truepower = False
            print("WE MESSED UP")
            return "NO"
        if truepower == True:
            return "YES"
    def deletethevmfile(self,vmname,walletname,verifyingsig,filename):
        truepower = True
        try:
         self.wallets[walletname]["verifyingkey"].verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
        except:
            truepower = False
            print("WE MESSED UP")
        delete_file_from_vm(vmname,filename)
    def getthevmIP(self,vmname,walletname,verifyingsig):
        truepower = True
        try:
         self.wallets[walletname]["verifyingkey"].verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )
        except:
            truepower = False
        if truepower == True:
            return VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"]
    def CHECKIFVMDATATRANSFERFULL(self,vmname,walletname,verifyingsig):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True:
            DATA = "Internetspeedused: "+str(self.vmdatalistalt[walletname]["VMNAMES"][vmname]["InternetSpeedUsed"])
            return DATA
    def CHECKIFVMDATASTORAGEFULL(self,vmname,walletname,verifyingsig):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True:
            datahere = requests.post(url="http://"+str(VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"])+":8002/gettheTOTALUSABLESTORAGE",json={})
            datajson = datahere.json()
            DATA = "STORAGEUSED: "+str(datajson["Success"])
            return DATA
    def CHECKIFVMRAMFULL(self,vmname,walletname,verifyingsig):
        verifyingkey = self.wallets[walletname]["verifyingkey"]
        truepower = True
        try:
         verifyingkey.verify(
          verifyingsig,
          vmname.encode('utf-8'),
          ec.ECDSA(hashes.SHA256())
         )

        except:
         truepower = False
        if truepower == True:
            datahere = requests.post(url="http://"+str(VMDATALIST[VMDATALIST2[vm_name]["String"]]["IP"])+":8002/gettheTOTALUSABLERAM",json={})
            datajson = datahere.json()
            DATA = "STORAGEUSED: "+str(datajson["Success"])
            return DATA
    def gettimeadded(self):
        return self.serverlist[str(get_local_ip())+":"+str(SPECIALPORT)]["timeadded"]
serverthingthing = serverthing()
@app.route("/createwallet",methods=['POST'])
def makeawallet():
    data = request.json  # Get the JSON data from the POST request

    # Check if the required data is present in the request
    if "walletname" not in data or "publickey" not in data:
        if "walletname" not in data:
            print("WALLETNAME MISSING")
        if "publickey" not in data:
            print("DATA: "+str(data))
            print("PUBLICKEY MISSING")
        return jsonify({"error": "Missing walletname or publickey"}), 400
        
    walletname = data["walletname"]
    publickey = data["publickey"]
    publickey = publickey.encode('utf-8')

    # Now you can use the data to create the wallet using your serverthing instance
    try:
     getwalletcoins = serverthingthing.getwalletbalance(walletname)
     return jsonify({"Error":"Stop making wallets that ALREADY EXIST!"}),403
    except:
        print("SUCCESSFUL WALLET CREATION")
    serverthingthing.createwallet(walletname, publickey)

    # Return the encrypted message in the response
    servers = serverthingthing.getservers()
    serverlen = len(servers)
    walletsignatureveri = serverthingthing.getverificationkey(walletname)
    servernum1 = random.randint(min(servers),max(servers))
    servernum2 = random.randint(min(servers),max(servers))
    data = {
              "walletname": walletname,
              "verificationkey": publickey.decode('utf-8')
            }

# Sending the POST request
    url1 = ""
    try:
     url1 = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/createwalletwithallthatdata"
    except:
            
            servernum1 = random.randint(min(servers),max(servers))
    repeattimes = 0
    try:
     
     response = requests.post(url1, json=data)
     print("RESPONSE: "+str(response))
     if response.status_code == 200:
        print("Successful")
     del servers[servernum1]
    except Exception as e:
        print("ERROR: "+str(e))
        lol=True
    try:
      del servers[servernum1]
    except:
        print("OK THEN")
        return jsonify({"Success":"We made the wallet, but there are no servers to send to"}),200
    servernum2 = random.randint(min(servers),max(servers))
    url2 = serverthingthing.getprotocol(servers[servernum2])+servers[servernum2]+"/createwalletwithallthatdata"
    try:
     response = requests.post(url2,json=data)
     print("RESPONSE: "+str(response))

     if response.status_code == 200:
        print("Successful")
     
     del servers[servernum2]
    except Exception as e:
        print("ERROR: "+str(e))
        lol=True
        del servers[servernum2]

    return jsonify({"Success":"Done"}),200

@app.route("/getfiles",methods=['POST'])
def getfiles():
 vm = request.json
 vm = vm["vm"]
 return jsonify(files[vm])
@app.route("/getcommands",methods=['POST'])
def getcommands():
 vm = request.json
 vm = vm["vm"]
 return jsonify(commands[vm])
@app.route("/getfile",methods=['POST'])
def getfile():
    file = request.json
    file = file["Name"]
    if os.path.abspath(file).find(abspathvariable)>-1:

     return send_file(file)
    else:
     return "Not allowed."
@app.route("/addfiletousedlist",methods=['POST'])
def addfiletousedlist():
    filesplusvms = request.json
    file = filesplusvms["File"]
    vm = filesplusvms["vm"]
    labelfileasused(file,vm)
    return "YOU DID IT"
@app.route("/addcommandtousedlist",methods=['POST'])
def addcommandtousedlist():
    commandsplusvms = request.json
    command = commandsplusvms["Command"]
    vm = commandsplusvms["vm"]
    labelfileasused(command,vm)
    return "YOU DID IT"        
@app.route("/getfilespace",methods=['POST'])
def getfilespace():
    data=request.json
    if "walletname" not in data or "verifyingsig" not in data:
        return jsonify({"Error":"YOU MESSED UP BIG TIME!"}),405
    filespace = serverthingthing.getfilespaceamount(data["walletname"],data["verifyingsig"])
    return jsonify({"Success":str(filespace)}),200
@app.route("/createwalletwithallthatdata",methods=["POST"])
def makethatwallet():
   walletname = ""
   client_ip = request.remote_addr
   response = serverthingthing.checkifthinginserverlist(client_ip)
   if response == "YES!":
    data = request.json
    if "walletname" not in data or "verificationkey" not in data:
      return jsonify({"error":"Missing walletname or verificationkey"}),400
    walletname = str(data["walletname"])
    verificationkey = data["verificationkey"]
    verificationkey = verificationkey.encode('utf-8')
    walletcreate = serverthingthing.createwalletotherreason(walletname,verificationkey)
    print("WALLETCREATIONREASON: "+str(walletcreate))
    try:
           print(serverthingthing.getwalletbalance(walletname))
    except:
        return jsonify({"Error":"IT DIDNT SUCCEED!!!!!!!!!!!#32232323232"},500)
    servers = serverthingthing.getservers()
    serverlen = len(servers)
    try:
     servernum1 = random.randint(int(min(servers)),int(max(servers)))
    except:
     servernum1 = int(min(servers))
    try:
     servernum2 = random.randint(0,serverlen-1)
    except:
     servernum2 = int(min(servers))
    validity = True
    INVALIDTHING1 = True
    INVALIDTHING2 = True
    while servernum1 == servernum2:
        if servernum2+1<= serverlen:
            servernum2+=1
        else:
            servernum2+=-1
    if serverlen>1:
     while INVALIDTHING1 == True:
      # Endpoint URL
      url1 = ""
      try:
       url1 = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/verifywalletexistence"
      except:
          servernum1 = random.randint(int(min(servers)),int(max(servers)))
          url1 = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/verifywalletexistence"

# JSON data to send in the POST request
      data = {
    "walletname": walletname,
    "verificationkey":data["verificationkey"]
      }

# Sending the POST request
      try:
        replooptimes = 0
        replooptimes+=1
        if replooptimes==10:
             del servers[servernum4]
             url1 = ""
        response = requests.post(url1, json=data)
        if response.status_code == 200:
         validity = response.json()
         print("Wallet validity:", validity)
         validity = validity["Success"]
         if validity == "NO":
            INVALIDTHING1 = False
            data = {
              "walletname": walletname,
              "verificationkey": data[
                  "verificationkey"]
            }

# Sending the POST request
            url1 = ""
            try:
             url1 = serverthingthing.getprotocol(servers[servernum1])+servers[int(servernum1)]+"/createwalletwithallthatdata"
            except:
                print("SERVERS: "+str(servers))
                del servers[servernum1]
                servernum1 = random.randint(int(min(servers)),int(max(servers)))
                url1 = serverthingthing.getprotocol(servers[servernum1])+servers[int(servernum1)]+"/createwalletwithallthatdata"

            try:
             response = requests.post(url1, json=data)
             if response.status_code == 200:
              print("Wallet creation successful!")
              print(response.json())  # Print the response content
              del servers[servernum1]
            except:
                INVALIDTHING1 = True
                INVALIDTHING2 = True
                del servers[servernum1]
                serverlen = len(servers)
                servernum1 = random.randint(0,serverlen-1)
                return {"E"}

# Checking the response
           
            else:
             print("Error:", response.json())
             response2 = requests.post(url1,json=data)
            if response2.status_code == 200:
             print("Wallet creation successful!")
             print(response.json())
            else:
             print("Error: ",response.json())
            del servers[servernum1]
         else:
          if not serverlen == 0:
           del servers[servernum1]
           serverlen = len(servers)
           try:
            if int(min(servers)) == int(max(servers)):
                servernum1 = int(min(servers))
            else:
             servernum1 = random.randint(int(min(servers)),int(max(servers)))
           except Exception as e:
              print("SERVERS: "+str(servers))

              print("ERROR: "+str(e))

              return jsonify({"Success":"But we did fail in sending to another server"}),200
          else:
              INVALIDTHING1 = True
              INVALIDTHING2 = True
              print("OK")
              break
          break
        else:
         servernum1 = -1
             
         if servernum1 == servernum2:
            INVALIDTHING1 = True
            if servernum1>serverlen-1:
                servernum1+=-1
            else:
                servernum1+=1
         del servers[servernum2]
         break
      except:
          del servers[servernum1]
          INVALIDTHING1 = False
          INVALIDTHING2 =False

# Checking the response
     
    while INVALIDTHING2 == True:
        url2 = ""
        try:
         url2 = serverthingthing.getprotocol(servers[servernum2])+servers[int(servernum2)]+"/verifywalletexistence"
        except:
          servernum2 = random.randint(int(min(servers)),int(max(servers)))
          url2 = serverthingthing.getprotocol(servers[servernum2])+servers[int(servernum2)]+"/verifywalletexistence"

# JSON data to send in the POST request
        data = {
         "walletname": walletname,
         "verificationkey": data["verificationkey"]

        }

# Sending the POST request
        try:
         replooptimes = 0
         replooptimes+=1
         if replooptimes==10:
             del servers[servernum2]
             url1 = ""
         response = requests.post(url2, json=data)
         if response.status_code == 200:
          validity = response.json()
          print("Wallet validity:", validity)
          validity = validity["Success"]

          if validity == "NO":
            INVALIDTHING2 = False
            data = {
              "walletname": walletname,
              "verificationkey": data["verificationkey"]
            }

# Sending the POST request
            url2 = serverthingthing.getprotocol(servers[servernum2])+servers[int(servernum2)]+"/createwalletwithallthatdata"
            try:
             response = requests.post(url2, json=data)
             del servers[servernum2]
             if response.status_code == 200:
              print("Wallet creation successful!")
              print(response.json())  # Print the response content
             else:
              print("Error:", response.json())
             try:
              response2 = requests.post(url1,json=data)
             except:
                 del servers[servernum2]
                 serverlen = len(servers)
                 try:
                  servernum2 = random.randint(min(servers),serverlen-1)
                  if response2.status_code == 200:
                   print("Wallet creation successful!")
                   print(response.json())
                   INVALIDTHING2 = False
                  else:
                   print("Error: ",response.json)
                 except:
                                   return jsonify({"Success":"But we did fail in sending to another server"}),200

                 INVALIDTHING2 = True
                 
            except:
                del servers[servernum2]
                serverlen = len(servers)
                try:
                   if int(min(servers)) == int(max(servers)):
                    servernum2 = min(servers)
                   else:
                    servernum2 = random.randint(int(min(servers)),int(max(servers)))
                except Exception as e:
                 print("SERVERS: "+str(servers))
                 print("ERROR: "+str(e))
                 return jsonify({"Success":"But we did fail in sending to another server"}),200

                INVALIDTHING2 = True
    

# Checking the response
            
         else:
          if serverlen>0:
           del servers[servernum2]
           serverlen = len(servers)
           servernum2 = random.randint(min(servers),serverlen-1)
          else:
           servernum2 = -1
           INVALIDTHING2 = False
           break
          break
         break
        except:
            INVALIDTHING2 = False
    else:
        return jsonify({"Error":"Cant do"}),404
# Checking the response
        
       





    if not url1 == -1:
     url1 = servers[servernum1]
    if not url2 == -1:
     url2 = servers[servernum2]
    del servers[servernum1]
    del servers[servernum2]
    serverlen = len(servers)
    INVALIDTHING3 = True
    servernum3 = random.randint(min(servers),serverlen-1)

    if serverlen>1:
       while INVALIDTHING3 == True:
        url1 = serverthingthing.getprotocol(servers[servernum3])+servers[servernum3]+"/verifywalletexistence"

# JSON data to send in the POST request
        data = {
        "walletname": walletname
        }

# Sending the POST request
        try:
         response = requests.post(url1, json=data)
         replooptimes = 0
         replooptimes+=1
         if replooptimes==10:
             del servers[servernum3]
             url1 = ""
         if response.status_code == 200:
          validity = response.json()
          print("Wallet validity:", validity)
          if validity == "NO":
            INVALIDTHING3 = False
            data = {
              "walletname": walletname,
              "verificationkey": verificationkey
            }

# Sending the POST request
            url2 = serverthingthing.getprotocol(servers[servernum3])+servers[servernum3]+"/createwalletwithallthatdata"
            try:
             response = requests.post(url2, json=data)
            except:
                del servers[servernum1]
                serverlen = len(servers)
                try:
                   if int(min(servers)) == int(max(servers)):
                    servernum3 = min(servers)
                   else:
                    servernum3 = random.randint(min(servers),max(servers))
                except Exception as e:
                 print("ERROR: "+str(e))
                 return jsonify({"Success":"But we did fail in sending to another server"}),200


                INVALIDTHING3 = True
    

# Checking the response
            if response.status_code == 200:
             print("Wallet creation successful!")
             print(response.json())  # Print the response content
            else:
             print("Error:", response.json())
             try:
              response2 = requests.post(url1,json=data)
              if response2.status_code == 200:
               print("Wallet creation successful!")
               print(response.json())
             except:
                 del servers[servernum3]
                 serverlen = len(servers)
                 try:
                  servernum3 = random.randint(int(min(servers)),int(max(servers)))
                 except:
                                   return jsonify({"Success":"But we did fail in sending to another server"}),200

                 INVALIDTHING3=False
         
           
           
         else:
          if serverlen>0:
           del servers[servernum3]
           serverlen = len(servers)
           servernum3 = random.randint(min(servers.values()),serverlen-1)
          else:
           servernum3 = -1
          break

        except:
            INVALIDTHING3 = False
    del servers[servernum3]
    serverlen = len(servers)
    INVALIDTHING4 = True
    servernum4 = random.randint(min(servers.values()),serverlen-1)

    if serverlen>1:
       while INVALIDTHING4 == True:
        url1 = serverthingthing.getprotocol(servers[servernum4])+servers[servernum4]+"/verifywalletexistence"

# JSON data to send in the POST request
        data = {
        "walletname": walletname
        }

# Sending the POST request
        try:
         replooptimes = 0
         replooptimes+=1
         if replooptimes==10:
             del servers[servernum4]
             url1 = ""
         response = requests.post(url1, json=data)
         if response.status_code == 200:
          validity = response.json()
          print("Wallet validity:", validity)
          if validity == "NO":
            INVALIDTHING3 = False
            data = {
              "walletname": walletname,
              "verificationkey": verificationkey
            }

# Sending the POST request
            url2 = serverthingthing.getprotocol(servers[servernum4])+servers[servernum4]+"/createwalletwithallthatdata"
            try:
             response = requests.post(url2, json=data)
            except:
                del servers[servernum4]
                serverlen = len(servers)
                try:
                   if int(min(servers)) == int(max(servers)):
                    servernum4 = min(servers)
                   else:
                    servernum4 = random.randint(min(servers),max(servers))
                except Exception as e:
                 print("ERROR: "+str(e))
                 return jsonify({"Success":"But we did fail in sending to another server"}),200

                INVALIDTHING4 = True
    

# Checking the response
            if response.status_code == 200:
             print("Wallet creation successful!")
             print(response.json())  # Print the response content
            else:
             print("Error:", response.json())
             try:
              response2 = requests.post(url1,json=data)
              if response2.status_code == 200:
               print("Wallet creation successful!")
               print(response.json())
             except:
                 del servers[servernum4]
                 serverlen = len(servers)
                 try:
                  servernum4 = random.randint(min(servers),serverlen-1)
                 except:
                                   return jsonify({"Success":"But we did fail in sending to another server"}),200

                 INVALIDTHING4=False
         
           
           
         else:
          if serverlen>0:
           del servers[servernum4]
           serverlen = len(servers)
           servernum4 = random.randint(min(servers),serverlen-1)
          else:
           servernum4 = -1
          break

        except:
            INVALIDTHING4 = False 
    else:
        return jsonify({"Error":"Cant do"}),404
    del servers[servernum4]
    serverlen = len(servers)
    INVALIDTHING5 = True
    servernum5 = random.randint(min(servers.values()),serverlen-1)

    if serverlen>1:
       while INVALIDTHING5 == True:
        url1 = serverthingthing.getprotocol(servers[servernum5])+servers[servernum5]+"/verifywalletexistence"

# JSON data to send in the POST request
        data = {
        "walletname": walletname
        }

# Sending the POST request
        try:
         replooptimes = 0
         replooptimes+=1
         if replooptimes==10:
             del servers[servernum5]
             url1 = ""
         response = requests.post(url1, json=data)
         if response.status_code == 200:
          validity = response.json()
          print("Wallet validity:", validity)
          if validity == "NO":
            INVALIDTHING3 = False
            data = {
              "walletname": walletname,
              "verificationkey": verificationkey
            }

# Sending the POST request
            url2 = serverthingthing.getprotocol(servers[servernum5])+servers[servernum5]+"/createwalletwithallthatdata"
            try:
             response = requests.post(url2, json=data)
            except:
                del servers[servernum5]
                serverlen = len(servers)
                try:
                   if int(min(servers)) == int(max(servers)):
                    servernum5 = min(servers)
                   else:
                    servernum5 = random.randint(min(servers),max(servers))
                except Exception as e:
                 print("ERROR: "+str(e))
                 return jsonify({"Success":"But we did fail in sending to another server"}),200

                INVALIDTHING5 = True
    

# Checking the response
            if response.status_code == 200:
             print("Wallet creation successful!")
             print(response.json())  # Print the response content
            else:
             print("Error:", response.json())
             try:
              response2 = requests.post(url1,json=data)
              if response2.status_code == 200:
               print("Wallet creation successful!")
               print(response.json())
             except:
                 del servers[servernum5]
                 serverlen = len(servers)
                 try:
                  servernum5 = random.randint(min(servers.values()),serverlen-1)
                 except:
                                   return jsonify({"Success":"But we did fail in sending to another server"}),200

                 INVALIDTHING5=False
         
           
           
         else:
          if serverlen>0:
           del servers[servernum5]
           serverlen = len(servers)
           servernum5 = random.randint(min(servers.values()),serverlen-1)
          else:
           servernum5 = -1
          break

        except:
            INVALIDTHING5 = False 
    else:
        return jsonify({"Error":"Cant do"}),404
    return jsonify({"Success":"It Works!"}),200
   else:
       print("WE HAVE MESSED UP. WE HAVE MESSED UP.   ")
   
   print(serverthingthing.getwalletbalance(walletname))
   return jsonify({"Success":"YES!"}),200

# JSON data to send in the POST request
@app.route("/addtransaction",methods=['POST'])
def makethetransaction():
        data = request.json

        # Check if the required data is present in the request
        

        # Check if the required data is present in the request
        required_fields = ["Sender", "Reciever", "amountofcoins", "transactionfee", "verifyingsig", "txextra"]
        if not all(field in data for field in required_fields): 
            return jsonify({"Error":"WHERE IS IT!"}),404
        sender = data["Sender"]
        receiver = data["Reciever"]
        coins = data["amountofcoins"]  # Ensure proper data type for coins
        transactionfee = data["transactionfee"]  # Ensure proper data type for transaction fee
        verifyingsig = data["verifyingsig"]
        verifyingsig3 = base64.b64decode(data["verifyingsig"])
        print("VERIFYINGSIG3: "+str(verifyingsig3))
        txextra = data["txextra"]

        verifyingkey = serverthingthing.getverificationkey(sender)
        verifyingkeyloader = str(verifyingkey)
        stufflist = ''
        for i in range(len(verifyingkeyloader)-59):
                   stufflist = stufflist+verifyingkeyloader[i+30]
        
        thingpower = ''
        Devicet = stufflist

        Num1 = 0
        Num2 = 0
        wentthroughnum = -1
        Devicex = ""
        devicey = ""
               
        neothing = {}
        for item in stuffindata:
               if not item == '/':
                  neothing[1] = str(item)
               
               
        for item in Devicet:
                wentthroughnum+=1
                if item == neothing[1] and Num1==0:
                 Num1 = wentthroughnum
               
                if wentthroughnum == Num1+1 and item == 'n' and Num1>0:
                 Num2 = wentthroughnum
        
        Devicet = Devicet.replace(neothing[1],'')
        Devicet = delete_fifth_character(Devicet,Num2)
        thingpower33 = '''-----BEGIN PUBLIC KEY-----
REPLACE
-----END PUBLIC KEY-----'''
        wentthroughnum2 = -1
        for item in Devicet:
           if wentthroughnum2<Num1-1:
                 wentthroughnum2+=1
    
                 Devicex = Devicex+item
    
           else:
                 break
               
              
        print(Devicex)
        wentthroughnum3 = -1
        for item in Devicet:
         wentthroughnum3+=1
         if wentthroughnum3>=Num1:
               devicey+=item
               thingpower = Devicex+'\n'+devicey
        
               thingpower33 = thingpower33.replace('REPLACE',thingpower)
        print(thingpower33)
        thingpower33 = '-----BEGIN PUBLIC KEY-----\n'+str(thingpower)+'\n-----END PUBLIC KEY-----'
        print(thingpower33)
        messagething22 = ''
        verifyingkey = load_pem_public_key(thingpower33.encode('utf-8'), default_backend())
        messagething22 = str(sender) + str(receiver) + str(coins) + str(transactionfee) + str(txextra)
        messagething22 = messagething22.encode('utf-8')
        messagefind = str(transactionfee).find(".")
        if messagefind == -1:
             messagething22 = str(sender) + str(receiver) + str(coins) + str(transactionfee)+".0" + str(txextra)
             messagething22 = messagething22.encode('utf-8')
        well = True
        try:
            print("MESSAGETHING22: "+str(messagething22))
            verifyingkey.verify(
                verifyingsig3,
                messagething22,
                ec.ECDSA(hashes.SHA256())
            )
            serverresponse = serverthingthing.addtransactionstopendingtransactions(sender,receiver,coins,transactionfee,txextra,verifyingsig3)
            if serverresponse == "L" or serverresponse== "FAIL":
                print("SERVERRESPONSE: "+str(serverresponse))
                return jsonify({"Error":"NO WORKY"}),403
            if well == True:
              
              print("YES")
              servers = serverthingthing.getservers()

              print("OK")
              serverlen = len(servers)
              try:
               del servers[str(get_local_ip)+str(SPECIALPORT)]
              except:
                  print("NOOOOOOOOOO!!!!!")
              print(serverlen)
              if serverlen > 1:

               serverswentthrough = 0
               for servernum1 in range(serverlen):
                replooptimes = 0
                
                try:
                 messagething = ''
                 messagething = str(sender) + str(receiver) + str(coins) + str(transactionfee) + str(txextra)
                 messagething = hashlib.sha256(messagething.encode('utf-8')).hexdigest()
                 print("MESSAGETHING: "+str(messagething))
                 data = {"TransactionHash":messagething}
                 replooptimes+=1
                 print("REPLOOPTIMES: "+str(replooptimes))
                 if replooptimes == 2:
                     del servers[servernum1]
                     servernum1+=1
                 try:
                  try:
                      with open("SUPERPOWERFILED.txt","r") as file:
                          fileread = str(file.read())
                          if fileread == serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkfortransactionexistence":
                              del servers[servernum1]
                              print("ENEMY SPOTTED!")
                              servernum1+=1
                  except:
                      print("No enemy spotted.")
                  with open("SUPERPOWERFILED.txt","w") as file:
                      file.write(serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkfortransactionexistence")
               
                  thing = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[servernum1] + "/checkfortransactionexistence", json=data)
                  if thing.status_code == 200:
                   thing = thing.json()
                   print("THINGDATA: "+str(thing))
                   if thing["Success"] == "NO":
                    data = {
                        "Sender": sender,
                        "Reciever": receiver,
                        "amountofcoins": int(coins),
                        "transactionfee": int(transactionfee),
                        "verifyingsig": verifyingsig,
                        "txextra": txextra,
                        
                    }
                    try:
                     if servernum1>serverlen:
                         servernum = servernum%serverlen
                     POWERREQUEST = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[(servernum1)] + "/addtransaction", json=data)
                     if POWERREQUEST.status_code == 403:
                         del servers[servernum1]
                         servernum+=1
                     if POWERREQUEST.status_code == 200:
                         del servers[servernum1]
                         servernum1+=1
                         serverswentthrough+=1

                     print("POWERREQUEST:"+str(POWERREQUEST.json()))
                     print("200")
                    except Exception as e:
                        print("ERROR: "+str(e))
                    
                    if serverswentthrough == 5:
                        break
                  else:
                      print("WE TRIED SO HARD YET WE CAN'T SUCCEED!")
                 except:
                     lol=True
                 
                except Exception as e:
                    print("LOL")
                    print("ERROR"+str(e))
                    return jsonify({"Error":"You messed up!"}),403
                try:
                 del servers[servernum1]
                except:
                    print("ALREADY DELETED.")

        except Exception as e:
            well = True
            print("ERROR: "+str(e))
            return jsonify({"Error":"You messed up!"}),404

        # Rest of your code goes here...

        # Returning a success response if everything is fine
        return jsonify({"Success":"YOU DID IT!"}),200








@app.route("/checkforblockdatainthing",methods=["POST"])
def checkforblockdata():
 print("Request: "+str(request))
 client_ip = request.remote_addr+str(":8002")
 response = serverthingthing.checkifthinginserverlist(client_ip)
 if response == "YES!":
    data = request.json
    if "Hash" not in data:
        return jsonify({"Error":"Where is the hash?????"}),403
    haash = data["Hash"]
    responsething = serverthingthing.checkforblockdata(haash)
    return jsonify({"Success":responsething})
 else:
     return jsonify({"Error":"THIS IS NOT THE RIGHT WAY!"}),403
@app.route("/recieveblockdata2",methods=["POST"])
def addthatdata():
 response = "YES!"
 if response == "YES!":
    data = request.json
    if "blockdata" not in data:
        return jsonify({"Error":"You messed up."}),403
    blockdata = data["blockdata"]
    serverip = data["serverip"]
    blockhash = hashlib.sha256(str(blockdata).encode('utf8')).hexdigest()
    with open("PASTTHISPIECE2.txt","w") as file:
        file.write("PAST THIS PIECE")
    serverthingthing.addblockdatatoblock(blockdata,blockhash)
    with open("PASTTHISPIECE.txt","w") as file:
        file.write("PAST THIS PIECE")
    servers = serverthingthing.getservers()
    serverlen = len(servers)
    servernum1 = random.randint(0,serverlen-1)
    servernum2 = random.randint(0,serverlen-1)
    servernum1allowed = False
    servernum2allowed = False
    servernum3allowed = False
    servernum4allowed = False
    servernum5allowed = False
    with open("GOTPASTTHAT.txt","w") as file:
        file.write("Got past that")
    listofnumstodelete = []
    for item in servers:
       if servers[item] == serverip:
           listofnumstodelete.append(item)
       if servers[item] == SpecialDomain:
           listofnumstodelete.append(item)
       if servers[item] == "127.0.0.1:8254":
           listofnumstodelete.append(item)
    with open("listofnumstodelete.txt","w") as file:
        file.write(str(listofnumstodelete))
    with open("PastThisAswell7.txt","w") as file:
       file.write("Even past this.")
    for item in listofnumstodelete:
       if not item in servers:
           with open("Servershere.txt","w") as file:
               file.write(str(servers))
           with open("Itemhere.txt","w") as file:
               file.write(str(item))
       if len(servers)>0:
        del servers[item]
       else:
        return jsonify({"Success":"But there's no servers to send to"}),200
    servers = fixserverset(servers)

    with open("PastThisAswell8.txt","w") as file:
       file.write("Even past this.")

    try:
     if SpecialDevice == 2:
       del servers[str(get_local_ip())]
     else:
       del servers[SpecialDomain]
    except Exception as e:
     lol=True
    with open("PastThisAswell9.txt","w") as file:
       file.write("Even past this.")
    if len(servers) == 0:
       return jsonify({"Success":"But there's no servers to send to"}),200
    while servernum1allowed == False:
       if not servernum1 == -1 and servernum1 in servers:
        URL = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/checkforblockdatainthing"
        data = {"Hash":blockhash}

        try:
          response = requests.post(URL,json=data)
          if response.status_code == 200:
            validity = response.json()
            validity = validity["Success"]
            if validity == "NO":
                servernum1allowed = True
            else:
              if not serverlen == 0:
                print("OVER HERE, ITS HERE")
                del servers[servernum1]
                serverlen = len(servers)
                servernum1 = random.randint(0,serverlen)
              else:
                servernum1 = -1
                break
              if servernum1 == servernum2:
                  servernum1allowed = False
                  if servernum1>serverlen-1:
                      servernum1+=-1
                  else:
                      servernum1+=1

        except:
            print("OK ITS HERE")
            servernum1allowed = True
            servernum2allowed = True
            servernum1 = -1
            servernum2 = -1
       else:
            break
    while servernum2allowed == False:
       if not servernum2 == -1 and servernum2 in servers:
        URL = serverthingthing.getprotocol(servers[servernum2])+servers[servernum2]+"/checkforblockdatainthing"
        data = {"Hash":blockhash}

        try:
          response = requests.post(URL,json=data)
          if response.status_code == 200:
            validity = response.json()
            validity = validity["Success"]
            if validity == "NO":
                servernum2allowed = True
            else:
              if not serverlen == 0:
                print("OVER HERE, ITS HERE 2")

                del servers[servernum2]
                serverlen = len(servers)
                servernum2 = random.randint(0,serverlen)
              else:
                servernum2 = -1
                break
              if servernum1 == servernum2:
                  servernum2allowed = False
                  if servernum1>serverlen-1:
                      servernum2+=-1
                  else:
                      servernum2+=1
        except:
            print("OK ITS HERE.2")

            servernum1allowed = True
            servernum2allowed = True
            servernum1 = -1
            servernum2 = -1
       else:
            break

    url1 = ""
    if not servernum1 in servers:
        servernum1 = random.randint(0,len(servers)-1)
    if not servernum1 == -1 and int(servernum1) in servers:
     url1 = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/recieveblockdata2"
    else:
               print("OH NO: "+str(servers))
               print("SERVERNUM1: "+str(servernum1))
               lol=True

    url2 = ""
    if not servernum2 == -1 and int(servernum2) in servers:
     url2 = serverthingthing.getprotocol(servers[servernum2])+servers[servernum2]+"/recieveblockdata2"
    else:
                print("....")
                lol=True

    blockdataset = {"blockdata":blockdata,"serverip":"127.0.0.1:8254"}
    try:
     response1 = requests.post(url1,json=blockdataset)
     response2 = requests.post(url2,json=blockdataset)
    except Exception as e:
        print("Error: "+str(e))
        return {"Error: "+str(e)},403
        lol=True
    try:
        del servers[servernum1]
    except:
        lol=True
    try:
        del servers[servernum2]
    except:
        lol=True

    servernum3 = random.randint(min(servers),max(servers))
    serverlen = len(servers)
    if serverlen>0:
     while servernum3allowed == False:
      if not servernum3 == -1 and servernum3 in servers:

        try:
          response = requests.post(URL,json=data)
          if response.status_code == 200:
            validity = response.json()
            validity = validity["Success"]
            if validity == "NO":
                servernum3allowed = True
            else:
              if not serverlen == 0:
                del servers[servernum3]
                serverlen = len(servers)
                servernum3 = random.randint(min(servers),max(servers))
              else:
                servernum3 = -1
                break
              if servernum1 == servernum2:
                  servernum2allowed = False
                  if servernum1>serverlen-1:
                      servernum2+=-1
                  else:
                      servernum2+=1
        except:
            servernum3allowed = True
            servernum4allowed = True
            servernum5allowed = True
            servernum3= -1
      else:
            break
     if not servernum3 == -1 and servernum3 in servers:
        URL = serverthingthing.getprotocol(servers[servernum3])+servers[servernum3]+"/checkforblockdatainthing"
        data = {"Hash":blockhash}
     try:
        del servers[servernum3]
     except:
        lol=True
    servernum4 = 0
    try:
     servernum4 = random.randint(min(servers),max(servers))
    except:
                lol=True

    serverlen = len(servers)
    if serverlen>0:
     while servernum4allowed == False:

       if not servernum4 == -1 and servernum4 in servers:
        try:
          response = requests.post(URL,json=data)
          if response.status_code == 200:
            validity = response.json()
            validity = validity["Success"]
            if validity == "NO":
                servernum4allowed = True
            else:
              if not serverlen == 0:
                del servers[servernum4]
                serverlen = len(servers)
                servernum4 = random.randint(min(servers),max(servers))
              else:
                servernum4 = -1
                break
              if servernum1 == servernum2:
                  servernum2allowed = False
                  if servernum1>serverlen-1:
                      servernum2+=-1
                  else:
                      servernum2+=1
        except:
            servernum3allowed = True
            servernum4allowed = True
            servernum5allowed = True
            servernum4= -1
       else:
            break
     if not servernum4 == -1 and servernum4 in servers:
        URL = serverthingthing.getprotocol(servers[servernum4])+servers[servernum4]+"/checkforblockdatainthing"
        data = {"Hash":blockhash}
     try:
        del servers[servernum4]
     except:
        lol=True
    try:
     servernum5 = random.randint(min(servers),max(servers))
    except:
        lol=True
    serverlen = len(servers)
    if serverlen>0:
     while servernum5allowed == False:

       if not servernum5 == -1 and servernum5 in servers:
        try:
          response = requests.post(URL,json=data)
          if response.status_code == 200:
            validity = response.json()
            validity = validity["Success"]
            if validity == "NO":
                servernum5allowed = True
            else:
              if not serverlen == 0:
                del servers[servernum5]
                serverlen = len(servers)
                servernum5 = random.randint(min(servers),max(servers))
              else:
                servernum5 = -1
                break
              if servernum1 == servernum2:
                  servernum2allowed = False
                  if servernum1>serverlen-1:
                      servernum2+=-1
                  else:
                      servernum2+=1
        except:
            servernum3allowed = True
            servernum4allowed = True
            servernum5allowed = True
            servernum5= -1
       else:
            break
     if not servernum5 == -1 and servernum5 in servers:
        URL = serverthingthing.getprotocol(servers[servernum5])+servers[servernum5]+"/checkforblockdatainthing"
        data = {"Hash":blockhash}
     try:
        del servers[servernum5]
     except:
        lol=True

    return jsonify({"Success": "Block data added successfully"}),200
 else:
     return jsonify({"Error":"SYSTEM FAILED"}),403

@app.route("/recieveservers",methods=["GET"])
def getthoseservers():
    servers = serverthingthing.getservers()
    if len(servers) == 0:
        selfip = get_local_ip()
        servers["0"] = {str(selfip)}
    return jsonify({"Success":servers}),200
@app.route("/checktimeadded",methods=['GET'])
def checktimeadded():
    timeadded=serverthingthing.gettimeadded()
    return jsonify({"Success":str(timeadded)})
@app.route("/getaveragetransactionfee",methods=['GET'])
def gettransactionfee():
    averagetransactionfee = serverthingthing.gettheavgtransactionfee()
    return jsonify({"Success":averagetransactionfee})
@app.route("/recieveserverhash",methods=["GET"])
def getserverhash():
    servers = serverthingthing.getservers()
    table_string = "\n".join(servers)
    return jsonify({"Success":hashlib.sha256(table_string.encode('utf8')).hexdigest()})
@app.route("/getverifyingkeyspluswallets",methods=["GET"])
def getthosekeys():
    walletspluskeys = serverthingthing.getverifyingchecklist()
    return jsonify({"Success":walletspluskeys})

@app.route("/verifywalletexistence",methods=["POST"])
def checkwallet():
 client_ip = request.remote_addr
 response = serverthingthing.checkifthinginserverlist(client_ip)
 if response == "YES!":
    data = request.json
    if "walletname" not in data:
        return jsonify({"Error":"Forgot wallet name"})
    walletname = data["walletname"]
    validity = serverthingthing.checkforwallet(walletname)
    return jsonify({"Success":validity})
@app.route("/getwalletbalance",methods=["POST"])
def getwalletbalance():
    data = request.json
    if "walletname" not in data:
        return jsonify({"Error":"Forgot wallet name"})
    walletname = data["walletname"]
    balance = serverthingthing.getwalletbalance(walletname)
    return jsonify({"Success":balance})

    serverthingthing.serversallowedtoaddtorequestlist(responsepawn,ip_address,typed)
@app.route("/getthewalletofthis",methods=["GET"])
def getthewalelt():
     wallet = serverthingthing.getselfwallet()
     if wallet == "":
         return jsonify({"Error":"IMPOSSIBLE."}),400
     return jsonify({"Success":wallet})
servers = serverthingthing.getservers()

@app.route("/addnewserver",methods=["POST"])
def addserver():
    client_ip = request.remote_addr
    data = request.json
    if not "type" in data or not "IP" in data or not "fileprice" in data or not "Verifyingkey" in data or not "ramgbprice" in data or not "vcpuprice" in data or not "datatransferprice" in data or not "PortThing" in data or not "PROTOCOL" in data:
        print("DATA: "+str(data))
        return jsonify({"Error":"error error pumpkin terror"}),493
    if not data["PROTOCOL"] == "http://" and not data["PROTOCOL"] == "https://":
        return jsonify({"Error":"WE FAILED"}),403
    if data["type"] == 1:
     IP2 = data["IP"]
     MINERCHECK = data["MINERCHECK"]
     NODECHECK = data["NODECHECK"]
     Fileprice = data["fileprice"]
     ramgbprice = data["ramgbprice"]
     vcpuprice = data["vcpuprice"]
     datatransferprice = data["datatransferprice"]
     Verifyingkey = data["Verifyingkey"]
     PROTOCOL = data["PROTOCOL"]
     print("VERIFYINGKEY: "+str(Verifyingkey))
     Verifyingkey2 = str(Verifyingkey)
     Verifyingkey = load_pem_public_key(convertthething(Verifyingkey.encode("utf-8")).encode('utf-8'),backend=default_backend)
     PortThing = data["PortThing"]
     serverthingthing.listserver(client_ip,IP2,Fileprice,Verifyingkey,ramgbprice,vcpuprice,datatransferprice,PortThing,MINERCHECK,NODECHECK,Verifyingkey2,PROTOCOL)
     servers = serverthingthing.getservers()
     serverlen = len(servers)

     servernum1 = random.randint(0,serverlen-1)
     servernum2 = random.randint(0,serverlen-1)
     SERVERNUM1TRUE = False
     SERVERNUM2TRUE = False
     SERVERNUM3TRUE = False
     SERVERNUM4TRUE = False
     SERVERNUM5TRUE = False
     while SERVERNUM1TRUE == False:
         url = servers[servernum1]+"/addnewserver"
         data = {"IP2":IP2,"fileprice":Fileprice,"Verfiyingkey":Verifyingkey2,"IP":client_ip,"type":2,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
         try:
          response1 = requests.post(url,json=data)
          if response1.status_code == 200:
           if response1 == "NO":
              SERVERNUM1TRUE = True
          else:
              del servers[servernum1]
              serverlen = len(servers)
              servernum1 = random.randint(0,serverlen-1)
         except:
             SERVERNUM1TRUE = True
         
     while SERVERNUM2TRUE == False:
         url = servers[servernum2]
         data = {"IP":url}
         try:
          response2 = requests.post(url,json=data)
          if response2.status_code == 200:
           if response2 == "NO":
              SERVERNUM2TRUE = True
           else:
              del servers[servernum2]
              serverlen = len(servers)
              servernum2 = random.randint(0,serverlen-1)
         except:
             SERVERNUM2TRUE = True
         
     if servernum1 == servernum2:
       if servernum1 == serverlen-1:
           servernum1+=-1
       else:
           servernum1+=1
     url1 = serverthingthing.getprotocol(servers[servernum1])+servers[servernum1]+"/addnewserver"
     url2 = serverthingthing.getprotocol(servers[servernum2])+servers[servernum2]+"/addnewserver"
     data = {"type":2,"IP":client_ip,"IP2":IP2,"fileprice":Fileprice,"Verifyingkey":Verifyingkey2,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,
             "PortThing":PortThing,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
     try:

      requests.post(url1,json=data)
     except Exception as e:
      print("OH NO WHAT THE HECK OH NO!: "+str(e))
     try:
      requests.post(url2,json=data)
     except Exception as e:
         print("OH NO WHAT THE HECK OH NO!2: "+str(e))
         lol=True
     try:
         del servers[servernum1]
     except:
         lol=True
     try:
         del servers[servernum2]
     except:
         lol=True
     servernum3 = random.randint(min(servers),max(servers))
     serverlen = len(servers)
     if serverlen>0:
        url = ""
        while SERVERNUM3TRUE == False:
         url = serverthingthing.getprotocol(servers[servernum3])+servers[servernum3]+"/addnewserver"
         data = {"IP2":IP2,"fileprice":Fileprice,"Verfiyingkey":Verifyingkey2,"IP":client_ip,"type":2,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
         try:
          response1 = requests.post(url,json=data)
          if response1.status_code == 200:
              SERVERNUM3TRUE = True
          else:
              del servers[servernum1]
              serverlen = len(servers)
              servernum3 = random.randint(min(servers),max(servers))
         except:
             SERVERNUM3TRUE = True
         try:
          del servers[servernum3]
         except:
          lol=True
     try:
      servernum4 = random.randint(min(servers),max(servers))
     except:
          print("THERE ARENT ENOUGH SERVERS!")
     serverlen = len(servers)
     if serverlen>0:
        url = ""
        while SERVERNUM4TRUE == False:
         url = serverthingthing.getprotocol(servers[servernum4])+servers[servernum4]+"/addnewserver"
         data = {"IP2":IP2,"fileprice":Fileprice,"Verfiyingkey":Verifyingkey2,"IP":client_ip,"type":2,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
         try:
          response1 = requests.post(url,json=data)
          if response1.status_code == 200:
              SERVERNUM4TRUE = True
          else:
              del servers[servernum4]
              serverlen = len(servers)
              servernum4 = random.randint(min(servers),max(servers))
         except:
             SERVERNUM4TRUE = True
         try:
          del servers[servernum4]
         except:
          lol=True
     try:
      servernum5     = random.randint(min(servers),max(servers))
     except:
         print("THERE AREN'T ENOUGH SERVERS!")
     serverlen = len(servers)
     if serverlen>0:
        url = ""
        while SERVERNUM5TRUE == False:
         url = serverthingthing.getprotocol(servers[servernum5])+servers[servernum5]+"/addnewserver"
         data = {"IP2":IP2,"fileprice":Fileprice,"Verfiyingkey":Verifyingkey2,"IP":client_ip,"type":2,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
         try:
          response1 = requests.post(url,json=data)
          if response1.status_code == 200:
              SERVERNUM5TRUE = True
          else:
              del servers[servernum4]
              serverlen = len(servers)
              servernum5 = random.randint(min(servers),max(servers))
         except:
             SERVERNUM5TRUE = True
         try:
          del servers[servernum5]
         except:
          lol=True  

         
     try:
         del servers[servernum2]
     except:
         lol=True
     BLOCKTHING = serverthingthing.getmaxproprosedblock()
     if not BLOCKTHING == "LOLNO!":
      print("BLOCKTHING: "+str(BLOCKTHING))
      Blockhash = BLOCKTHING["Blockhash"]
      FirstSender = BLOCKTHING["FirstSender"]
      Serverip = BLOCKTHING["Serverip"]
      Timecreated = BLOCKTHING["Timecreated"]
      Blockdata = BLOCKTHING["Blockdata"]
      
      data4 = {"Blockhash":Blockhash,
                "FirstSender":FirstSender,
                "Serverip":Serverip,
                "Timecreated":Timecreated,
                "Blockdata":Blockdata,
                }
      time.sleep(7)
      try:
       requests.post(serverthingthing.getprotocol(data["IP"])+data["IP"]+":"+str(PortThing)+"/addmaxblockthing")
      except Exception as e:
          print("EPICFAIL!: "+str(e))
     else:
         print("I'm sorry bill, but I can't let you do that.")
    elif data["type"] == 2:
      if not "IP2" in data:
          return jsonify({"Error":"Stop being an idiot."})
      servervalue =  serverthingthing.checkifthinginserverlist(client_ip)
      fileprice = data["fileprice"]
      verifyingkey = data["Verifyingkey"]
      ramgbprice = data["ramgbprice"]
      vcpuprice = data["vcpuprice"]
      datatransferprice = data["datatransferprice"]
      PortThing = data["PortThing"]
      MINERCHECK = data["MINERCHECK"]
      NODECHECK = data["NODECHECK"]
      PROTOCOL = data["PROTOCOL"]
      IP2 = data["IP2"]
      if servervalue == "YES!":
        Verifyingkey = load_pem_public_key(convertthething(verifyingkey.encode('utf-8')).encode('utf-8'),backend=default_backend)

        serverthingthing.listserver(data["IP"],data["IP2"],fileprice,Verifyingkey,ramgbprice,vcpuprice,datatransferprice,PortThing,MINERCHECK,NODECHECK,verifyingkey,PROTOCOL)
        servers = serverthingthing.getservers()
        serverlen = len(servers)
        servernum1 = random.randint(0,serverlen-1)
        servernum2 = random.randint(0,serverlen-1)
        SERVERNUM1TRUE = False
        SERVERNUM2TRUE = False
        SERVERNUM3TRUE = False
        SERVERNUM4TRUE = False
        SERVERNUM5TRUE = False
        if servernum1 == servernum2:
         if servernum1 == serverlen-1:
           servernum1+=-1
         else:
           servernum1+=1
        while SERVERNUM1TRUE == False:
         url = ""
         try:
          url = servers[servernum1]
         except:
             servernum1 = random.randint(0,serverlen-1)
         data2 = {"SERVERIP":url}
         try:
          response1 = requests.post(serverthingthing.getprotocol(url)+url+"/checkforserverinserverlist",json=data2)
          
          if response1.status_code == 200:
           if response1 == "NO":
              SERVERNUM1TRUE = True
           else:
              del servers[servernum1]
              serverlen = len(servers)
              servernum1 = random.randint(0,serverlen-1)
          else:
              del servers[servernum1]
              serverlen = len(servers)
              servernum1 = random.randint(0,serverlen-1)
         except:
             SERVERNUM1TRUE = True
             SERVERNUM2TRUE = True

        while SERVERNUM2TRUE == False:
         url = ""
         try:
          url = servers[servernum2]
         except:
             servernum2 = random.randint(0,serverlen-1)
         data2 = {"SERVERIP":url}
         try:
          response2 = requests.post(serverthingthing.getprotocol(url)+url+"/checkforserverinserverlist",json=data2)
          if response2.status_code == 200:
           if response2 == "NO":
              SERVERNUM2TRUE = True
            
           else:
              del servers[servernum2]
              serverlen = len(servers)
              servernum2 = random.randint(0,serverlen-1)
          else:
              del servers[servernum2]
              serverlen = len(servers)
              servernum2 = random.randint(0,serverlen-1)
         except:
             SERVERNUM2TRUE = True
        if servernum1 == servernum2:
          if servernum1 == serverlen-1:
           servernum1+=-1
          else:
           servernum1+=1
        
      
        if servernum1>=0:
         try:
          url1 = +servers[servernum1]+"/addnewserver"
         except:
             print("We've run out of servers here")
        if servernum2>=0:
         try:
          url2 = serverthingthing.getprotocol(servers[servernum2])+servers[servernum2]+"/addnewserver"
         except:
             print("We've run out of servers HERE!!!")
        data3 = {"type":2,"IP":data["IP"],"IP2":IP2,"fileprice":fileprice,"Verifyingkey":verifyingkey,"ramgbprice":ramgbprice,"vcpuprice":vcpuprice,"datatransferprice":datatransferprice,"PortThing":PortThing,"MINERCHECK":MINERCHECK,"NODECHECK":NODECHECK,"PROTOCOL":"http://"}
        try:
         requests.post(url1,json=data3)
        except:
         lol=True
        try:
         requests.post(url2,json=data3)
        except:
            lol=True
        try:
         del servers[servernum1]
        except:
            lol=True
        try:
         del servers[servernum2]
        except:
            lol=True
        serverlen = len(servers)
        if serverlen>0:
           servernum3 = random.randint(min(servers),max(servers))
           while SERVERNUM3TRUE == False:
            url = ""
            try:
             url = servers[servernum3]
            except:
             servernum3 = random.randint(min(servers),max(servers))
            data2 = {"SERVERIP":url}
            try:
             response2 = requests.post(serverthingthing.getprotocol(url)+url+"/checkforserverinserverlist",json=data2)
             if response2.status_code == 200:
              if response2 == "NO":
               SERVERNUM3TRUE = True
            
              else:
               del servers[servernum3]
               serverlen = len(servers)
               servernum3 =random.randint(min(servers),max(servers))
             else:
              del servers[servernum3]
              serverlen = len(servers)
              servernum3= random.randint(min(servers),max(servers))
            except:
             SERVERNUM3TRUE = True
        url3 = ""
        if servernum3>=0:
         try:
          url3 = serverthingthing.getprotocol(servers[servernum3])+servers[servernum3]+"/addnewserver"
         except:
             print("We've run out of servers HERE!!!!!")
      
        try:
         requests.post(url3,json=data3)
        except:
            lol=True
        try:
            del servers[servernum3]
        except:
            lol=True
        servers = len(servers)
        if serverlen>0:
           servernum4 = random.randint(min(servers),max(servers))
           while SERVERNUM4TRUE == False:
            url = ""
            try:
             url = servers[servernum4]
            except:
             servernum4 = random.randint(min(servers),max(servers))
            data2 = {"SERVERIP":url}
            try:
             response2 = requests.post(serverthingthing.getprotocol(url)+url+"/checkforserverinserverlist",json=data2)
             if response2.status_code == 200:
              if response2 == "NO":
               SERVERNUM4TRUE = True
            
              else:
               del servers[servernum4]
               serverlen = len(servers)
               servernum4 =random.randint(min(servers),max(servers))
             else:
              del servers[servernum4]
              serverlen = len(servers)
              servernum4= random.randint(min(servers),max(servers))
            except:
             SERVERNUM4TRUE = True
        url4 = ""
        if servernum4>=0:
         try:
          url4 = serverthingthing.getprotocol(servers[servernum4])+servers[servernum4]+"/addnewserver"
         except:
             print("We've run out of servers HERE!!!!!")
        
        try:
         requests.post(url4,json=data3)
        except:
            lol=True
        try:
            del servers[servernum4]
        except:
            lol=True
        servers = len(servers)
        if serverlen>0:
           servernum5 = random.randint(min(servers),max(servers))
           while SERVERNUM5TRUE == False:
            url = ""
            try:
             url = servers[servernum5]
            except:
             servernum5 = random.randint(min(servers),max(servers))
            data2 = {"SERVERIP":url}
            try:
             response2 = requests.post(serverthingthing.getprotocol(url)+url+"/checkforserverinserverlist",json=data2)
             if response2.status_code == 200:
              if response2 == "NO":
               SERVERNUM5TRUE = True
            
              else:
               del servers[servernum5]
               serverlen = len(servers)
               servernum5 =random.randint(min(servers),max(servers))
             else:
              del servers[servernum5]
              serverlen = len(servers)
              servernum5= random.randint(min(servers),max(servers))
            except:
             SERVERNUM5TRUE = True
        url5 = ""
        if servernum5>=0:
         try:
          url5 = serverthingthing.getprotocol(servers[servernum5])+servers[servernum5]+"/addnewserver"
         except:
             print("We've run out of servers HERE!!!!!")
       
        try:
         requests.post(url5,json=data3)
        except:
            lol=True
        BLOCKTHING = serverthingthing.getmaxproprosedblock()
        if not BLOCKTHING == "LOLNO!":
         print("STUFFINTHEBLOCK: "+str(BLOCKTHING))

         haash = BLOCKTHING["Blockhash"]
         firstsender = BLOCKTHING["FirstSender"]
         serverip = BLOCKTHING["Serverip"]
         timecreated = BLOCKTHING["Timecreated"]
         blockdata = BLOCKTHING["Blockdata"]
         data4 = {"haash":haash,
                "firstsender":firstsender,
                "serverip":serverip,
                "timecreated":timecreated,
                "blockdata":blockdata,
             }
         try:
          requests.post(serverthingthing.getprotocol(data["IP"])+data["IP"]+"/addmaxblockthing")
         except:
            lol=True
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/doesitwork",methods=['GET'])
def doesitwork():
    data = serverthingthing.checkhashstringvalidation()
    return jsonify({"Response":data}),200

@app.route("/recieveblockdata1",methods=["POST"])
def addthedata():
 response = "YES!"
 if response == "YES!":
   data = request.json
   if "hash" not in data or "Firstsender" not in data or "Serverip" not in data or "Timecreated" not in data or "NodesPassedThrough" not in data or "Signature" not in data:
     return jsonify({"Error":"You messed up."})
   haash = data["hash"]
   sender = data["Firstsender"]
   serverip = data["Serverip"]
   timecreated = data["Timecreated"]
   NodesPassedThrough = data["NodesPassedThrough"]
   Signature = data["Signature"]

   with open("GotTohere999.txt","w") as file:
       file.write("Got Over Here")
   check = serverthingthing.checkforserverinblock(serverip,haash)
   with open("GotPastThis.txt","w") as file:
       file.write("Past this thing")

   if check == "YES":
       return jsonify({"Error":"THIS SHOULDNT BE HERE!"}),403
   with open("PastThisAswell.txt","w") as file:
       file.write("Even past this.")
   serverthingthing.addforcorrectblockcount(haash,sender,serverip,timecreated,NodesPassedThrough,Signature)

   with open("pastthisanyways.txt","w") as file:
       file.write("PASTTHIS")
   with open("countdownthing.txt","r") as file:
            countdownthing = float(file.read())
   countdownthing+=countdownthing*-1
   countdownthing+=3
   with open("PastThisAswell2.txt","w") as file:
       file.write("Even past this.")
   servers = serverthingthing.getservers()
   with open("PastThisAswell3.txt","w") as file:
       file.write("Even past this.")
   serverlen = len(servers)
   with open("PastThisAswell4.txt","w") as file:
       file.write("Even past this.")

   with open("PastThisAswell5.txt","w") as file:
       file.write("Even past this.")
   servernum1valid = False
   servernum2valid = False
   servernum3valid = False
   servernum4valid = False
   servernum5valid = False
   with open("PastThisAswell6.txt","w") as file:
       file.write("Even past this.")
   listofnumstodelete = []
   for item in servers:
       if servers[item] == serverip:
           listofnumstodelete.append(item)
       if servers[item] == SpecialDomain:
           listofnumstodelete.append(item)
       if servers[item] == "127.0.0.1:8254":
           listofnumstodelete.append(item)
   
   with open("PastThisAswell77.txt","w") as file:
       file.write("Even past this.")
   for item in listofnumstodelete:
       del servers[item]
   servers = fixserverset(servers)
   serverlen = len(servers)

   servernum1 = random.randint(0,serverlen-1)
   servernum2 = random.randint(0,serverlen-1)
   with open("PastThisAswell88.txt","w") as file:
       file.write("Even past this.")

   try:
    if SpecialDevice == 2:
       del servers[str(get_local_ip())]
    else:
       del servers[SpecialDomain]
   except Exception as e:
     lol=True
   with open("PastThisAswell99.txt","w") as file:
       file.write("Even past this.")
   if len(servers) == 0:
       return jsonify({"Success":"But there's no servers to send to"}),200
   if servernum1 == servernum2 and not servernum1 == 1:
     if servernum1<serverlen:
         servernum2+=1
     else:
         servernum2+=-1
   if servernum1 == servernum2 and not servernum1 == 1:
     if servernum1<serverlen:
         servernum2+=1
     else:
         servernum2+=-1
   data1 = {"Hash":haash,"Port":str(SPECIALPORT),"Type":2,"SpecialDomain":SpecialDomain}
   replooptimes = 0
   usedurls = []
   
   while servernum1valid == False:
     url = ""
     try:
      url = servers[servernum1]
     except Exception as e:
         print("Error: "+str(e))
     if url in usedurls:

         servernum1valid = True
         del servers[servernum1]
         return jsonify({"Success":"But we ran out of servers"}),200

     if replooptimes >= 10:
         servernum1valid = True
         del servers[servernum1]
         return jsonify({"Success":"But we ran out of servers"}),200

     replooptimes+=1
     if len(servers)<1:

         servernum1valid = True
         del servers[servernum1]




     replooptimes2 = 0

     try:

      if replooptimes2 >= 10:

         del servers[servernum1]
         servernum1valid = True
         return jsonify({"Success":"But we ran out of servers"}),200

      replooptimes2+=1
      print("Server: "+str(serverthingthing.getprotocol(url)+url+"/checkforblockexistence"))
      responsepawn = requests.post(serverthingthing.getprotocol(url)+url+"/checkforblockexistence",json=data1)
      print("Status code: "+str(responsepawn.status_code))
      print("Done")
      usedurls.append(url)

      if responsepawn.status_code == 200:
       validity = responsepawn.json()
       validity = validity["Success"]

       if validity == "NO":
         servernum1valid = True
       else:
           print("Ok thats why this is occurring, but how????")
           del servers[servernum1]
           try:
               servernum1 = random.randint(min(servers),max(servers))
           except:
                       lol=True

       if servernum1 == servernum2:
          servernum1valid = False
          if servernum1>serverlen-1:
              servernum1+=-1
          else:
              servernum1+=1
       else:
        if not serverlen == 0:
         print("Uhhh")
         serverlen = len(servers)
         try:
               servernum1 = random.randint(min(servers),max(servers))
         except:
                     lol=True

        else:
         servernum1 = -1
         break

      else:
          print("over here's a problem......")
          del servers[servernum1]
          try:
               servernum1 = random.randint(min(servers),max(servers))
          except:
                      lol=True

     except Exception as e:
         print("Error: "+str(e))
         return jsonify({"Success":"But we ran out of servers"}),200
         servernum1valid = True
         servernum2valid = True
         servernum1 = -1
         servernum2 = -1
   replooptimes = 0
   if not servernum2 in servers:
       servernum2valid = True
   while servernum2valid == False:

     url = servers[servernum2]
     if replooptimes == 10:

         servernum2valid = True
         break
     replooptimes+=1
     if len(servers)<1:

         servernum2valid = True
         break
     if url in usedurls:

         servernum2valid = True
         break
     replooptimes2 = 0
     try:

      if replooptimes2 >= 10:

         servernum2valid = True
         del servers[servernum2]
         break
      replooptimes2+=1
      responsepawn = requests.post(serverthingthing.getprotocol(url)+url+"/checkforblockexistence",json=data1)
      usedurls.append(url)
      if replooptimes2 >= 10:
         servernum1valid = True
         break
      replooptimes2+=1
      if responsepawn.status_code == 200:
       validity = response.json()
       validity = validity["Success"]
       if validity == "NO":
         servernum2valid = True

       else:
        if not serverlen == 0:
         del servers[servernum2]
         serverlen = len(servers)
         servernum2 = random.randint(1,serverlen)
        else:
            servernum2 = -1
            break
      else:
          del servers[servernum2]
          try:
               servernum2 = random.randint(min(servers),max(servers))
          except:
                      lol=True

     except:

         servernum1 = -1
         servernum2 = -1
         servernum2valid = True
         servernum1valid = True


   data = {
     "hash":haash,
      "Firstsender":sender,
      "Serverip":serverip,
      "Timecreated":timecreated,
      "NodesPassedThrough":NodesPassedThrough+1,
      "Signature":Signature}
   print("Servernum1: "+str(servernum1))
   if not servernum1 == -1:
    print("inside here alright")
    url1 = ""
    replooptimes3 = 3
    try:
     
     url1 = serverthingthing.getprotocol(servers[servernum1])+str(servers[servernum1])+"/recieveblockdata1"
    except Exception as e:
        print("Is this the true reason?"+str(e))
        print("Servers: "+str(servers))
        return jsonify({"Error":"NOOOOOO23!!!!!!"}),403
    with open("Gottothispoint.txt","w") as file:
        file.write("Got over here")
    try:
     responselol = requests.post(url1,json=data)
     with open("Gotthroughthis.txt","w") as file:
         file.write("Got through this.")
     if replooptimes3 == 3:
         del servers[servernum1]
         url1 = ""
     replooptimes3+=1

    except:

        return jsonify({"Error":"NOOOOOO3!!!!!!"}),403
   replooptimes3 = 0
   if not servernum2 == -1:
    url2 = ""
    try:
     url2 = serverthingthing.getprotocol(servers[servernum2])+str(servers[servernum2])+"/recieveblockdata1"
    except:
        return jsonify({"Error":"NOOOOOO233!!!!!!"}),403
    try:

     responselol2 = requests.post(url2,json=data)
     if replooptimes3 == 3:
         del servers[servernum2]
         url2 = ""
     replooptimes3+=1
    except:

        return jsonify({"Error":"NOOOOOO33!!!!!!"}),403
    try:
       del servers[servernum1]
    except:
        lol=True
    try:
       del servers[servernum2]
    except:
        lol=True
   serverlen = len(servers)

   if serverlen>0:
    servernum3 = 0
    try:
     servernum3 = random.randint(min(servers),max(servers))
    except:
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True

    replooptimes = 0
    while servernum3valid == False:
     if replooptimes == 10:
         break
     replooptimes+=1
     if len(servers)<1:
         break
     url = servers[servernum3]
     try:
      responsepawn = requests.post(serverthingthing.getprotocol(url)+url+"/checkforblockexistence",json=data1)

      if responsepawn.status_code == 200:
       validity = response.json()
       validity = validity["Success"]
       if validity == "NO":
         servernum3valid = True

       else:
        if not serverlen == 0:
         del servers[servernum3]
         serverlen = len(servers)
         servernum3 = random.randint(min(servers),max(servers))

        else:
            servernum3 = -1
            break
     except:
         servernum1 = -1
         servernum3 = -1
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True
         servernum1valid = True
    url3 = ""
    try:
     url3 = serverthingthing.getprotocol(servers[servernum3])+str(servers[servernum3])+"/recieveblockdata1"
    except:
                lol=True

    try:
     responselol2 = requests.post(url3,json=data)
    except:
                lol=True

   serverlen = len(servers)
   if serverlen>0:
    servernum4 = 0
    try:
     servernum4 = random.randint(min(servers),max(servers))
    except:
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True


    while servernum4valid == False:
     url = servers[servernum4]
     try:
      responsepawn = requests.post(serverthingthing.getprotocol(servers[servernum4])+url+"/checkforblockexistence",json=data1)

      if responsepawn.status_code == 200:
       validity = response.json()
       validity = validity["Success"]
       if validity == "NO":
         servernum4valid = True

       else:
        if not serverlen == 0:
         del servers[servernum4]
         serverlen = len(servers)
         servernum4 = random.randint(min(servers),max(servers))

        else:
            servernum4 = -1
            break
     except:
         servernum1 = -1
         servernum4 = -1
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True
         servernum1valid = True
    url4 = ""
    try:
     url4 = serverthingthing.getprotocol(servers[servernum4])+str(servers[servernum4])+"/recieveblockdata1"
    except:
                lol=True

    try:
     responselol2 = requests.post(url4,json=data)
    except:
                lol=True

    serverlen = len(servers)
   servernum5 = 0
   try:
     servernum5 = random.randint(min(servers),max(servers))
   except:
        lol=True
   if serverlen>0:
    servernum5 = 0
    try:
     servernum5 = random.randint(min(servers),max(servers))
    except:
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True


    while servernum5valid == False:
     url = servers[servernum5]
     try:
      responsepawn = requests.post(serverthingthing.getprotocol(url)+url+"/checkforblockexistence",json=data1)

      if responsepawn.status_code == 200:
       validity = response.json()
       validity = validity["Success"]
       if validity == "NO":
         servernum5valid = True

       else:
        if not serverlen == 0:
         del servers[servernum5]
         serverlen = len(servers)
         servernum5 = random.randint(min(servers),max(servers))

        else:
            servernum4 = -1
            break
     except:
         servernum1 = -1
         servernum4 = -1
         servernum3valid = True
         servernum4valid = True
         servernum5valid = True
         servernum1valid = True
    url5 = ""
    try:
     url5 = serverthingthing.getprotocol(servers[servernum5])+str(servers[servernum5])+"/recieveblockdata1"
    except:
                lol=True

    try:
     responselol2 = requests.post(url5,json=data)
    except:
                lol=True

   return jsonify({"Success":"WE DID IT!"}),200
 else:
     return jsonify({"Error":"NOOOOO4O!!!!!!"}),403

@app.route("/getalltheblocks",methods=["GET"])
def returnblocks():
   numberoftries = 0
   with open("numberoftries.txt","r") as file:
       try:
           numberoftries = int(file.read())
       except:
           print("The Time For Tries is Over.")
   database_path = 'blocklist.db'
   output_file = 'output_file.sql'+str(numberoftries)
   numberoftries+=1
   with open("numberoftries.txt","w") as file:
       file.write(str(numberoftries))
   export_sqlite_database(database_path, output_file)
   return send_file(output_file, as_attachment=True)
@app.route("/sendwalletlisthash",methods=['POST'])
def gethashnow():
    hashthingmachine = serverthingthing.generateavalidationhash()
    return jsonify({"Success":hashthingmachine})
@app.route("/gethashstringhash",methods=['POST'])
def getthisonenow():
    hashstringthing = serverthingthing.gethashstring()
    return jsonify({"Success":hashstringthing})
@app.route("/getsomeoftheblocks",methods=['POST'])
def getsomeoftheblocks():
    data = request.json
    if not "Blockamount" in data:
        return jsonify({"Error":"YOU DIDN'T PROVIDE A BLOCKAMOUNT......"}),403
    Blockamount = data["Blockamount"]
    blocks = serverthingthing.getblocksafterpoint(Blockamount)
    print("Blocks: "+str(blocks))
    return jsonify({"Success":blocks}),200
@app.route("/getoneoftheblocks",methods=['POST'])
def getoneoftheblocks():
    data = request.json
    if not "Blockamount" in data:
        return jsonify({"Error":"YOU DIDN'T PROVIDE A BLOCKAMOUNT......"}),403
    Blockamount = data["Blockamount"]
    block = serverthingthing.getonespecificblock(Blockamount)
    print("Block: "+str(block))
    return jsonify({"Success":block}),200
@app.route("/recieveservers2",methods=["GET"])
def getthoseservers2():
    servers = serverthingthing.getservers2()
    if len(servers) == 0:
        selfip = get_local_ip()
        servers["0"] = {str(selfip)}
    return jsonify({"Success":servers}),200
@app.route("/getblocknum",methods=['GET'])
def getblocknum():
    blocknum = serverthingthing.getblockamount()
    return jsonify({"Success":blocknum})
@app.route("/getverifyingkeynum",methods=['GET'])
def getverifyingkeynum():
    verifyingkeynum = serverthingthing.getkeythingamount()
    return jsonify({"Success":verifyingkeynum})
@app.route("/getalltheverifyingkeys", methods=['GET'])
def getverifyingkeylist():
    verifyingkeythinglist = serverthingthing.getverifyingchecklist()
    KEYDICT = {}
  
    KEYDICT = verifyingkeythinglist
    return jsonify({"Success": KEYDICT}), 200
    


@app.route("/getsomeoftheverifyingkeys",methods=['POST'])
def getsomeoftheverifyingkeylist():
    data = request.json
    if not "beginnum" in data:
        return jsonify({"Error":"YOU DIDN't put it in..."}),403
    beginnum = data["beginnum"]
    
    verifyingkeythinglist = serverthingthing.getsomeoftheverifyingchecklist(beginnum)
    KEYDICT = {}
    for item in verifyingkeythinglist.keys():
        KEYDICT[item] ={"verifyingkey":str(verifyingkeythinglist[item]["verifyingkey"]),"walletname":str(verifyingkeythinglist[item]["walletname"])}
    return jsonify({"Success":dict(KEYDICT)}),200
@app.route("/getsomeoftheverifyingkeysalt",methods=['POST'])
def getsomeoftheverifyingkeylistalt():
    data = request.json
    if not "beginnum" in data:
        return jsonify({"Error":"YOU DIDN't put it in..."}),403
    beginnum = data["beginnum"]
   
        
    verifyingkeythinglist = serverthingthing.getsomeoftheverifyingchecklistalt(beginnum,int(data["endnum"]))
    
    return jsonify({"Success":verifyingkeythinglist}),200
@app.route("/checkforserverinserverlist",methods=['POST'])
def checkforserverinserverlist():
    data = request.json
    if not "SERVERIP" in data:
        return jsonify({"Error":"Where is the IP????"})
    serverip = data["SERVERIP"]
    if serverthingthing.checkifthinginserverlist(serverip) == "YES!":
        return jsonify({"Success":"YES"})
    else:
        return jsonify({"Success":"NO"})
@app.route("/getblockchainstarttime",methods=['GET'])
def getbcst():
    timething = serverthingthing.getthetime()
    return jsonify({"Success":timething}),200
@app.route("/getthecurrent600thing",methods=['GET'])
def gettc6t():
    the600thing = 600
   
    the600thing = serverthingthing.the600get()
    return jsonify({"Success":the600thing})
@app.route("/getthealtthing",methods=['GET'])
def gettat():
    return jsonify({"Success":countdownthing})
@app.route("/addmaxblockthing",methods=['POST'])
def addmaxblockthing():
    data = request.json
    if not "haash" in data or not "firstsender" in data or not "serverip" in data or not "timecreated" in data or not "blockdata" in data or not "NodesPassedThrough" in data or not "Signature" in data:
        return jsonify({"Error":"NO YOU"})
    haash = data["haash"]
    firstsender = data["firstsender"]
    serverip = data["serverip"]
    timecreated = data["timecreated"]
    blockdata = data["blockdata"]
    NodesPassedThrough = data["NodesPassedThrough"]
    Signature = data["Signature"]
    serverthingthing.addforcorretblockcount(haash,firstsender,serverip,timecreated,NodesPassedThrough,signature)
    serverthingthing.addblockdatatoblock(blockdata)
    return jsonify({"Success":"YES"})

@app.route("/checkfortransactionexistence",methods=['POST'])
def checkthething():
    data = request.json
    if not "TransactionHash" in data:
        print("NO TRANSACTION HASH YOU")
        return jsonify({"Error":"NO TRANSACTIONHASH!"}),400
    transactionhash = data["TransactionHash"]
    result = serverthingthing.getransaction(transactionhash)
    return jsonify({"Success":result}),200
@app.route("/checkforwallettransactionamount",methods=['POST'])
def getthething():
    data = request.json
    if not "Walletname" in data:
        return jsonify({"Error":"Where is the wallet?"})
    walletname = data["Walletname"]
    transactionamount = serverthingthing.gettransactionamountfromwallet(walletname)
    return jsonify({"Success":transactionamount})
@app.route("/addfile",methods=['POST'])
def addthefile():
    data = request.json
    if not "filetype" in data or not "filename" in data or not "filedata" in data or not "walletname" in data or not "verifyingsig" in data or not "messagething" in data or not "dayslastingfor" in data:
        return {"Error":"WHERE ARE THE STUFFS?"}
    
    filename = data["filename"]
    filedata = data["filedata"]
    walletname = data["walletname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)

    messagething = data["messagething"]
    dayslastingfor = data["dayslastingfor"]
    filetype = data["filetype"]
    filehash = hashlib.sha256(filedata.encode('utf-8')).hexdigest()
    filesize = int(sys.getsizeof(filedata))
    sendthisthing = serverthingthing.startfiletransaction(filehash,verifyingsig,walletname,filesize,messagething,dayslastingfor,filedata,filename,filetype)
    return jsonify({"Success":sendthisthing}),200
@app.route("/finishfiletransaction",methods=['POST'])
def finishit():
    data = request.json
    if not "walletname" in data or not "transactionnum" in data or not "verifyingsig" in data or not "txextra" in data:
        return jsonify({"Error":"Missing data"}),400
 
    walletname = data["walletname"]
    transactionnum = data["transactionnum"]
    verifyingsig = data["verifyingsig"]
    txextra = data["txextra"]
    verifyingsig = base64.b64decode(verifyingsig)
    try:
     responseeey = serverthingthing.endthepend(walletname,transactionnum,verifyingsig,txextra)
     if not responseeey == "W":
         print("Response: "+str(responseeey))
         return jsonify({"Error":"WEEE MESSED UP!!!!!"}),403
   
    except Exception as E:
        print("ERROR: "+str(E))
        return jsonify({"Error":"YOU MESSED UP"}),405
    return jsonify({"Success":"WE SUCCEEDED"}),200
@app.route("/addtransactionfromsvronnetwork",methods=['POST'])
def addthatthing():
   client_ip = request.remote_addr
   responsething = serverthingthing.checkifthinginserverlist(client_ip)
   if responsething == "YES!":
    data = request.json
    if not "txextra" in data or not "Sender" in data or not "Reciever" in data or not "filesize" in data or not "fileprice" in data or not "dayslastingfor" in data or not "filehash" in data or not "verifyingsig1" in data or not "verifyingsig2" in data or not "transactionfee" in data or not "txextra2" in data:
        return jsonify({"Error":"WE ARE MISSING SOMETHING!!!"}),403
    txextra = data["txextra"]
    Sender = data["Sender"]
    Reciever = data["Reciever"]
    filesize = data["filesize"]
    fileprice = data["fileprice"]
    dayslastingfor = data["dayslastingfor"]
    filehash = data["filehash"]
    verifyingsig1 = data["verifyingsig1"]
    verifyingsig1 = base64.b64decode(verifyingsig1)
    verifyingsig2 = data["verifyingsig2"]
    verifyingsig2 = base64.b64decode(verifyingsig2)
    transactionfee = data["transactionfee"]
    txextra2 =data["txextra2"]
    serverdata = serverthingthing.addfiletransactionnotfrommainpc(txextra,Sender,Reciever,filesize,fileprice,dayslastingfor,filehash,verifyingsig1,verifyingsig2,transactionfee,txextra2)
    print("DATA: "+str(serverdata))
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/getfile",methods=['POST'])
def getthatfile():
    data = request.json
    if not "walletname" in data or not "filename" in data or not "verifyingsig" in data:
        return {"Error":"WHERE IS THE DATA!"}
    walletname = data["walletname"]
    filename = data["filename"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    datathing = serverthingthing.getfile(filename,verifyingsig,walletname)
    return jsonify({"Success":datathing})
@app.route("/getcountdown",methods=['GET'])
def getcountdown():
    return {"Success":timewaitthing}
@app.route("/startfilespacepurchase",methods=['POST'])
def initiatethething():
    data=request.json
    if not "Sender" in data or not "verifyingsig" in data or not "filespace" in data or not "daysoflasting" in data:
        return jsonify({"Error":"Where is the stuff?"}),403
    Sender = data["Sender"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    filespace = data["filespace"]
    daysoflasting = data["daysoflasting"]
    sendthisthingy = serverthingthing.buyfilestoragespacep1(filespace,verifyingsig,daysoflasting,Sender)
    print(sendthisthingy)
    return jsonify({"Success":sendthisthingy}),200
@app.route("/endfilespacepurchase",methods=['POST'])
def endthething():
    data = request.json
    if not "pendingtransactionnum" in data or not "verifyingsig" in data:
        return jsonify({"Error":"WHERE IS IT"}),403
    pendingtransactionnum = data["pendingtransactionnum"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    addthething = serverthingthing.buyfilestoragespacep2(pendingtransactionnum,verifyingsig)
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/addfilespacepurchasefromaltPC",methods=['POST'])
def addthetransaction():
    data = request.json
    server = request.remote_addr
    respone = serverthingthing.checkifthinginserverlist(server)
    if not respone == "YES!":
        return jsonify({"Error":"You aren't a server idiot."}),403
    if not "filespace" in data or not "daysoflasting" in data or not "txextra" in data or not "transactionfee" in data or not "filepricething" in data or not "verifyingsig1" in data or not "verifyingsig2" in data or not "pendingtransactionnum" in data or not "Sender" in data or not "Reciever" in data:
        if not "filespace" in data:
            print("FILESPACEFAIL")
        if not "daysoflasting" in data:
            print("DAYSOFLASTINGFAIL")
        if not "txextra" in data:
            print("TXEXTRAFAIL")
        if not "transactionfee" in data:
            print("TRANSACTIONFEEFAIL")
        if not "filepricething" in data:
            print("FILEPRICETHINGFAIL")
        if not "verifyingsig1" in data:
            print("VERIFYINGSIG1FAIL")
        if not "verifyingsig2" in data:
            print("VERIFYINGSIG2FAIL")
        if not "pendingtransactionnum" in data:
            print("PENDINGTRANSACTIONNUMFAIL")
        if not "Sender" in data:
            print("SENDERFAIL")
        if not "Reciever" in data:
            print("SENDERFAIL")
        return jsonify({"Error":"You're missing something"}),405
    filespace = data["filespace"]
    daysoflasting = data["daysoflasting"]
    txextra = data["txextra"]
    transactionfee = data["transactionfee"]
    filepricething = data["filepricething"]
    verifyingsig1 = data["verifyingsig1"]
    verifyingsig1 = base64.b64decode(verifyingsig1)
    verifyingsig2 = data["verifyingsig2"]
    verifyingsig2 = base64.b64decode(verifyingsig2)
    pendingtransactionnum = data["pendingtransactionnum"]
    Sender = data["Sender"]
    Reciever = data["Reciever"]
    serverthingthing.addfilespacetransactionfromaltPC(filespace,daysoflasting,txextra,transactionfee,filepricething,verifyingsig1,verifyingsig2,pendingtransactionnum,Sender,Reciever)
    return jsonify({"Success":"WE DID IT!!!"}),200
@app.route("/getaltfile",methods=['POST'])
def getaltfile():
    data = request.json
    if not "walletname" in data or not "verifyingsig" in data or not "filename" in data:
        return jsonify({"Error":"WHERE IS IT"})
    walletname = data["walletname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    filename = data["filename"]
    
    sendit = serverthingthing.getfilealt(walletname,verifyingsig,filename)
    return jsonify({"Success":sendit})
@app.route("/addfilealt",methods=['POST'])
def addfilealt():
    data=request.json
    
    if not "filedata" in data or not "filename" in data or not"walletname" in data or not "verifyingsig" in data or not "filetype" in data:
        return jsonify({"Error":"missingsomething"}),403
    filedata = data["filedata"]
    filename = data["filename"]
    walletname = data["walletname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    filetype = data["filetype"]
    filesize = int(sys.getsizeof(filedata))
    serverthingyyy = serverthingthing.addfilealt(filedata,filesize,filename,walletname,verifyingsig,filetype)
    print(serverthingyyy)
    return jsonify({"Success": "WE DID IT!"}),200
    
@app.route("/getfilepricechange",methods=['POST'])
def filepricechangeactivate():
    data=request.json
    
    if not "verifyingsig" in data or not "newfileprice" in data or not "server" in data:
        return jsonify({"Error":"You're missing something."})
    server = data["server"]
    verifyingkeything = serverthingthing.getverifyingkeyfromserver(server)
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    messagething = str(data["newfileprice"])
    truep2222 = True
    hashthingyyy = str(verifyingsig)+messagething
    hashthingyyy = hashlib.sha256(hashthingyyy.encode('utf8')).hexdigest()
    try:
     verifyingkeything.verify(
                         verifyingsig,
                         messagething.encode('utf-8'),
                         ec.ECDSA(hashes.SHA256())
     )
    except:
        print("there was a fialure")
        truep2222 = False
    if truep2222 == True:
        newfileprice = data["newfileprice"]
        serverthingthing.changeserverfileprice(newfileprice,server)
   
    sigthinglisty[hashthingyyy] = {"timeadded":time.time()}
    truethingyyy1 = True
    truethingyyy2 = True
    serverlist = serverthingthing.getservers()
    serverlen = len(serverlist)
    servernum1 = random.randint(0,serverlen-1)
    servernum2 = random.randint(0,serverlen-1)
    data1 = {"hashthingy":hashthingyyy}
    data2 = {"verifyingsig":verifyingsig,"newfileprice":data["newfileprice"],"server":data["server"]}
    if serverlen > 1:

               serverswentthrough = 0
               for servernum1 in range(serverlen):
                replooptimes = 0
                
                try:
            
                 data = {"hashthingy":hashthingyyy}
                 replooptimes+=1
                 print("REPLOOPTIMES: "+str(replooptimes))
                 if replooptimes == 2:
                     del servers[servernum1]
                     servernum1+=1
                 try:
                  try:
                      with open("SUPERPOWERFILED.txt","r") as file:
                          fileread = str(file.read())
                          if fileread == serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence":
                              del servers[servernum1]
                              print("ENEMY SPOTTED!")
                              servernum1+=1
                  except:
                      print("No enemy spotted.")
                  with open("SUPERPOWERFILED.txt","w") as file:
                      file.write(serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence")
               
                  thing = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[servernum1] + "/checkforactionexistence", json=data)
                  if thing.status_code == 200:
                   thing = thing.json()
                   print("THINGDATA: "+str(thing))
                   if thing["Success"] == "NO":
                    data5 = {"verifyingsig":verifyingsig,"newfileprice":data["newfileprice"],"server":data["server"]}
                    try:
                     if servernum1>serverlen:
                         servernum = servernum%serverlen
                     POWERREQUEST = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[(servernum1)] + "/getfilepricechange", json=data5)
                     if POWERREQUEST.status_code == 403:
                         del servers[servernum1]
                         servernum+=1
                     if POWERREQUEST.status_code == 200:
                         del servers[servernum1]
                         servernum1+=1
                         serverswentthrough+=1

                     print("POWERREQUEST:"+str(POWERREQUEST.json()))
                     print("200")
                    except Exception as e:
                        print("ERROR: "+str(e))
                    
                    if serverswentthrough == 5:
                        break
                  else:
                      print("WE TRIED SO HARD YET WE CAN'T SUCCEED!")
                 except:
                     lol=True
                 
                except Exception as e:
                    print("LOL")
                    print("ERROR"+str(e))
                    return jsonify({"Error":"You messed up!"}),403
                try:
                 del servers[servernum1]
                except:
                    print("ALREADY DELETED.")
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/getvcpupricechange",methods=['POST'])
def vcpupricechangeactivate():
    data=request.json
    if not "verifyingsig" in data or not "vcpuprice" in data or not "server" in data:
        return jsonify({"Error":"You're missing something."})
    server = data["server"]
    verifyingkeything = serverthingthing.getverifyingkeyfromserver(server)
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    messagething = str(data["vcpuprice"])
    truep2222 = True
    hashthingyyy = str(verifyingsig)+messagething
    hashthingyyy = hashlib.sha256(hashthingyyy.encode('utf8')).hexdigest()

    try:
     verifyingkeything.verify(
                         verifyingsig,
                         messagething.encode('utf-8'),
                         ec.ECDSA(hashes.SHA256())
     )
    except:
        truep2222 = False
    if truep2222 == True:
        newfileprice = data["vcpuprice"]
        serverthingthing.changeservervcpuprice(newfileprice,server)
   
    sigthinglisty[hashthingyyy] = {"timeadded":time.time()}
    truethingyyy1 = True
    truethingyyy2 = True
    serverlist = serverthingthing.getservers()
    serverlen = len(serverlist)
    servernum1 = random.randint(0,serverlen-1)
    servernum2 = random.randint(0,serverlen-1)
    data1 = {"hashthingy":hashthingyyy}
    data2 = {"verifyingsig":verifyingsig,"vcpuprice":data["vcpuprice"],"server":data["server"]}
    if serverlen > 1:

               serverswentthrough = 0
               for servernum1 in range(serverlen):
                replooptimes = 0
                
                try:
            
                 data = {"hashthingy":hashthingyyy}
                 replooptimes+=1
                 print("REPLOOPTIMES: "+str(replooptimes))
                 if replooptimes == 2:
                     del servers[servernum1]
                     servernum1+=1
                 try:
                  try:
                      with open("SUPERPOWERFILED.txt","r") as file:
                          fileread = str(file.read())
                          if fileread == serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence":
                              del servers[servernum1]
                              print("ENEMY SPOTTED!")
                              servernum1+=1
                  except:
                      print("No enemy spotted.")
                  with open("SUPERPOWERFILED.txt","w") as file:
                      file.write(serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence")
               
                  thing = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[servernum1] + "/checkforactionexistence", json=data)
                  if thing.status_code == 200:
                   thing = thing.json()
                   print("THINGDATA: "+str(thing))
                   if thing["Success"] == "NO":
                    data3 = {"verifyingsig":verifyingsig,"vcpuprice":data["vcpuprice"],"server":data["server"]}
                    try:
                     if servernum1>serverlen:
                         servernum = servernum%serverlen
                     POWERREQUEST = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[(servernum1)] + "/getvcpupricechange", json=data3)
                     if POWERREQUEST.status_code == 403:
                         del servers[servernum1]
                         servernum+=1
                     if POWERREQUEST.status_code == 200:
                         del servers[servernum1]
                         servernum1+=1
                         serverswentthrough+=1

                     print("POWERREQUEST:"+str(POWERREQUEST.json()))
                     print("200")
                    except Exception as e:
                        print("ERROR: "+str(e))
                    
                    if serverswentthrough == 5:
                        break
                  else:
                      print("WE TRIED SO HARD YET WE CAN'T SUCCEED!")
                 except:
                     lol=True
                 
                except Exception as e:
                    print("LOL")
                    print("ERROR"+str(e))
                    return jsonify({"Error":"You messed up!"}),403
                try:
                 del servers[servernum1]
                except:
                    print("ALREADY DELETED.")
    return jsonify({"Success":"WE DID IT!"}),200

@app.route("/getdatatransferpricechange",methods=['POST'])
def datatransferpricechangeactivate():
    data=request.json
    if not "verifyingsig" in data or not "datatransferprice" in data or not "server" in data:
        return jsonify({"Error":"You're missing something."})
    server = data["server"]
    verifyingkeything = serverthingthing.getverifyingkeyfromserver(server)
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    messagething = str(data["datatransferprice"])
    truep2222 = True
    hashthingyyy = str(verifyingsig)+messagething
    hashthingyyy = hashlib.sha256(hashthingyyy.encode('utf8')).hexdigest()

    try:
     verifyingkeything.verify(
                         verifyingsig,
                         messagething.encode('utf-8'),
                         ec.ECDSA(hashes.SHA256())
     )
    except:
        truep2222 = False
    if truep2222 == True:
        newfileprice = data["datatransferprice"]
        serverthingthing.changeserverDATATRANSFERGBprice(newfileprice,server)
   
    sigthinglisty[hashthingyyy] = {"timeadded":time.time()}
    truethingyyy1 = True
    truethingyyy2 = True
    serverlist = serverthingthing.getservers()
    serverlen = len(serverlist)
    servernum1 = random.randint(0,serverlen-1)
    servernum2 = random.randint(0,serverlen-1)
    data1 = {"hashthingy":hashthingyyy}
    data2 = {"verifyingsig":verifyingsig,"datatransferprice":data["datatransferprice"],"server":data["server"]}
    if serverlen > 1:

               serverswentthrough = 0
               for servernum1 in range(serverlen):
                replooptimes = 0
                
                try:
            
                 data = {"hashthingy":hashthingyyy}
                 replooptimes+=1
                 print("REPLOOPTIMES: "+str(replooptimes))
                 if replooptimes == 2:
                     del servers[servernum1]
                     servernum1+=1
                 try:
                  try:
                      with open("SUPERPOWERFILED.txt","r") as file:
                          fileread = str(file.read())
                          if fileread == serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence":
                              del servers[servernum1]
                              print("ENEMY SPOTTED!")
                              servernum1+=1
                  except:
                      print("No enemy spotted.")
                  with open("SUPERPOWERFILED.txt","w") as file:
                      file.write(serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence")
               
                  thing = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[servernum1] + "/checkforactionexistence", json=data)
                  if thing.status_code == 200:
                   thing = thing.json()
                   print("THINGDATA: "+str(thing))
                   if thing["Success"] == "NO":
                    data3 = {"verifyingsig":verifyingsig,"datatransferprice":data["datatransferprice"],"server":data["server"]}
                    try:
                     if servernum1>serverlen:
                         servernum = servernum%serverlen
                     POWERREQUEST = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[(servernum1)] + "/getdatatransferpricechange", json=data3)
                     if POWERREQUEST.status_code == 403:
                         del servers[servernum1]
                         servernum+=1
                     if POWERREQUEST.status_code == 200:
                         del servers[servernum1]
                         servernum1+=1
                         serverswentthrough+=1

                     print("POWERREQUEST:"+str(POWERREQUEST.json()))
                     print("200")
                    except Exception as e:
                        print("ERROR: "+str(e))
                    
                    if serverswentthrough == 5:
                        break
                  else:
                      print("WE TRIED SO HARD YET WE CAN'T SUCCEED!")
                 except:
                     lol=True
                 
                except Exception as e:
                    print("LOL")
                    print("ERROR"+str(e))
                    return jsonify({"Error":"You messed up!"}),403
                try:
                 del servers[servernum1]
                except:
                    print("ALREADY DELETED.")
   
@app.route("/getramgbpricechange",methods=['POST'])
def ramgbpricechangeactivate():
    data=request.json
    if not "verifyingsig" in data or not "ramgbprice" in data or not "server" in data:
        return jsonify({"Error":"You're missing something."})
    server = data["server"]
    verifyingkeything = serverthingthing.getverifyingkeyfromserver(server)
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    messagething = str(data["ramgbprice"])
    truep2222 = True
    hashthingyyy = str(verifyingsig)+messagething
    hashthingyyy = hashlib.sha256(hashthingyyy.encode('utf8')).hexdigest()

    try:
     verifyingkeything.verify(
                         verifyingsig,
                         messagething.encode('utf-8'),
                         ec.ECDSA(hashes.SHA256())
     )
    except:
        truep2222 = False
    if truep2222 == True:
        newfileprice = data["ramgbprice"]
        serverthingthing.changeserverRAMGBprice(newfileprice,server)
   
    sigthinglisty[hashthingyyy] = {"timeadded":time.time()}
    truethingyyy1 = True
    truethingyyy2 = True
    serverlist = serverthingthing.getservers()
    serverlen = len(serverlist)
    servernum1 = random.randint(0,serverlen-1)
    servernum2 = random.randint(0,serverlen-1)
    data1 = {"hashthingy":hashthingyyy}
    data2 = {"verifyingsig":verifyingsig,"ramgbprice":data["ramgbprice"],"server":data["server"]}
    if serverlen > 1:

               serverswentthrough = 0
               for servernum1 in range(serverlen):
                replooptimes = 0
                
                try:
            
                 data = {"hashthingy":hashthingyyy}
                 replooptimes+=1
                 print("REPLOOPTIMES: "+str(replooptimes))
                 if replooptimes == 2:
                     del servers[servernum1]
                     servernum1+=1
                 try:
                  try:
                      with open("SUPERPOWERFILED.txt","r") as file:
                          fileread = str(file.read())
                          if fileread == serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence":
                              del servers[servernum1]
                              print("ENEMY SPOTTED!")
                              servernum1+=1
                  except:
                      print("No enemy spotted.")
                  with open("SUPERPOWERFILED.txt","w") as file:
                      file.write(serverthingthing.getprotocol(servers[servernum1]) + str(servers[servernum1]) + "/checkforactionexistence")
               
                  thing = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[servernum1] + "/checkforactionexistence", json=data1)
                  if thing.status_code == 200:
                   thing = thing.json()
                   print("THINGDATA: "+str(thing))
                   if thing["Success"] == "NO":
                    try:
                     if servernum1>serverlen:
                         servernum = servernum%serverlen
                     POWERREQUEST = requests.post(serverthingthing.getprotocol(servers[servernum1]) + servers[(servernum1)] + "/getdatatransferpricechange", json=data2)
                     if POWERREQUEST.status_code == 403:
                         del servers[servernum1]
                         servernum+=1
                     if POWERREQUEST.status_code == 200:
                         del servers[servernum1]
                         servernum1+=1
                         serverswentthrough+=1

                     print("POWERREQUEST:"+str(POWERREQUEST.json()))
                     print("200")
                    except Exception as e:
                        print("ERROR: "+str(e))
                    
                    if serverswentthrough == 5:
                        break
                  else:
                      print("WE TRIED SO HARD YET WE CAN'T SUCCEED!")
                 except:
                     lol=True
                 
                except Exception as e:
                    print("LOL")
                    print("ERROR"+str(e))
                    return jsonify({"Error":"You messed up!"}),403
                try:
                 del servers[servernum1]
                except:
                    print("ALREADY DELETED.")
@app.route("/checkforblockexistence",methods=["POST"])
def checkforblocke():
 client_ip = request.remote_addr
 response = serverthingthing.checkifthinginserverlist(client_ip)
 if response == "YES!":
    data = request.json
    print("DATA: "+str(data))
    if "Hash" not in data or "Port" not in data:
        return jsonify({"Error": "Where is the Hash?????"}),403
    haash = data["Hash"]
    port = data["Port"]
    serverip = client_ip+":"+str(port)
    responsething = serverthingthing.checkforserverinblock(serverip,haash)
    return jsonify({"Success":responsething}),200
 else:
    return jsonify({"Error":"ERROR"}),403
@app.route("/checkforactionexistence",methods=['POST'])
def checkforactionexistence():
    data=request.json
    if not "hashthingy" in data:
        return jsonify({"Error":"Where is the hashthingy"})
    hashthingy = data["hashthingy"]
    if hashthingy in sigthinglisty:
        return jsonify({"Success":"It is in there."})
@app.route("/getcheapestCSP",methods=['POST'])
def getcheapestCSP():
    data=request.json
    if not "BannedServers" in data:
        return jsonify({"Error":"Where are your banned servers?"}),403
    bannedservers = data["BannedServers"]
    powerthing = serverthingthing.getcheapestCSP(bannedservers)
    return jsonify({"Success":powerthing})
@app.route("/getcheapestCSP2",methods=['POST'])
def getcheapestCSP2():
    data=request.json
    if not "BannedServers" in data:
        return jsonify({"Error":"Where are your banned servers?"}),403
    bannedservers = data["BannedServers"]
    powerthing = serverthingthing.getcheapestCSP2(bannedservers)
    return jsonify({"Success":powerthing}),200
@app.route("/getcheapestCSP3",methods=['POST'])
def getcheapestCSP3():
    data=request.json
    if not "BannedServers" in data:
        return jsonify({"Error":"Where are your banned servers?"}),403
    bannedservers = data["BannedServers"]
    powerthing = serverthingthing.getcheapestCSP3(bannedservers)
    return jsonify({"Success":powerthing}),200
@app.route("/getcheapestCSP4",methods=['POST'])
def getcheapestCSP4():
    data=request.json
    if not "BannedServers" in data:
        return jsonify({"Error":"Where are your banned servers?"}),403
    bannedservers = data["BannedServers"]
    powerthing = serverthingthing.getcheapestCSP4(bannedservers)
    return jsonify({"Success":powerthing}),200
@app.route("/getaltserversthisthingowns",methods=['GET'])
def getaltservers():
     altserversitowns = serverthingthing.getaltservers()
     return jsonify({"Success":altserversitowns}),200
@app.route("/addspecialblock",methods=['POST'])
def addspecialblock():
    data=request.json
    block=data["block"]
    serverthingthing.addaspecialblock(block)
    return jsonify({"Success":"WE DID IT!"})
@app.route("/deletevmfile",methods=['POST'])
def deletevmfile():
    data = request.json
    if not "verifyingsig" in data or not "walletname" in data or not"vmname" or not "filename" in data:
        return jsonify({"Error":"SOMETHING'S MISSING"}),403
    filename = data["filename"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    serverthingthing.deletethevmfile(data["vmname"],data["walletname"],verifyingsig,filename)
@app.route("/getIP",methods=['POST'])
def getIP():
    data = request.json
    if not "verifyingsig" in data or not "walletname" in data or not "vmname" in data:
        return jsonify({"Error":"You're missing something."}),403
    verifyingsig = data["verifyingsig"]
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(verifyingsig)
    IP = serverthingthing.getthevmIP(vmname,walletname,verifyingsig)
    return jsonify({"Success":IP}),200
@app.route("/startVMSTUFFTRANSACTION",methods=['POST'])
def startit():
    data=request.json
    if not "RAMGB" in data or not "DATASTORAGEGB" in data or not "VCPUS" in data or not "DATATRANSFERGB" in data or not "verifyingsig" in data or not "daysoflasting" in data or not "walletname" in data:
        return jsonify({"Error":"YOU MISSED SOMETHING!"}),403
    RAMPRICEGB = data["RAMGB"]
    DATASTORAGEGB = data["DATASTORAGEGB"]
    VCPUS = data["VCPUS"]
    DATATRANSFERGB = data["DATATRANSFERGB"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    daysoflasting2 = data["daysoflasting"]
    walletname = data["walletname"]
   
    
    print("LOL")
   
    TRUSTTHING = serverthingthing.startfilestufftransaction(DATATRANSFERGB,daysoflasting2,RAMPRICEGB,DATASTORAGEGB,walletname,VCPUS,verifyingsig)
  
    print("W")
    return jsonify({"Success":TRUSTTHING}),200

@app.route("/checkthe600thing",methods=['POST'])
def checkthe600thing():
      
          the600thing = 600
          with open("changethe600thing.txt","r") as file:
              the600thing = float(file.read())
       
          with open("changethe600thing.txt","w") as file:
              file.write(str(the600thing))    
          the600thing = the600thing-0.25
          with open("changethe600thing.txt","w") as file:
              file.write(str(the600thing))
          print("CHANGETHE600THING: "+str(changethat600thing))
          with open("changethe600thing.txt","r") as file:
              print("CHANGETHAT600THING: "+str(file.read()))
          if the600thing<0.25:
              serverthingthing.gothroughthetransactionlist()
              countdownthing = 3
              with open("countdownthing.txt","w") as file:
                  file.write(str(countdownthing))
              
          return jsonify({"Success":str(the600thing)})

@app.route("/checkthecountdowthing",methods=['POST'])
def checkthecountdowthing():
            
           
           with open("countdownthing.txt","r") as file:
            countdownthing = float(file.read())
           countdownthing-=0.25
           with open("countdownthing.txt","w") as file:
               file.write(str(countdownthing))
           if countdownthing <0.25:
               
               serverthingthing.acceptablockpuppy()
              
               countdownthing = 3
               with open("countdownthing.txt","w") as file:
                file.write(str(countdownthing))
               changethat600thing = 6
               
               with open("changethe600thing.txt","w") as file:
                file.write(str(6))
               with open("changethe600thing.txt","r") as file:
                   print("CHANGETHE600THING443433: "+str(file.read()))
           return jsonify({"Success":countdownthing}),200
@app.route("/gothroughtransactions",methods=['POST'])
def gothroughthat():
    serverthingthing.gothroughthetransactionlist()
    return jsonify({"Success":"IT WENT THROUGH!"})
@app.route("/getthecountdownthing",methods=['GET'])
def getthecountdownthing():
    countdownthing = 3
    with open("countdownthing.txt","r") as file:
        countdownthing = float(file.read())
    return jsonify({"Success":countdownthing}),200
@app.route("/endVMSTUFFTRANSACTION",methods=['POST'])
def endit():
    data=request.json
    if not "verifyingsig" in data or not "vmtransactionnum" in data:
        return jsonify({"Error":"YOU MISSED SOMETHING!"}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    vmtransactionnum = data["vmtransactionnum"]
    stuff = serverthingthing.endfilestufftransaction(verifyingsig,vmtransactionnum)
    print(stuff)
    return jsonify({"Success":stuff}),200
@app.route("/GETTRANSACTIONFROMALTPC",methods=['POST'])
def addthattransaction():
    data=request.json
    if not "Price" in data or not "txextra" in data or not "verifyingsig1" in data or not "verifyingsig2" in data or not "transactionfee" in data or not "sender" in data or not "reciever" in data or not "vmtransactionnum" in data:
        return jsonify({"Error":"WHERE IS IT!"}),403
    price = data["Price"]
    txextra = data["txextra"]
    verifyingsig1 = data["verifyingsig1"]
    verifyingsig1 = base64.b64decode(verifyingsig1)
    verifyingsig2 = data["verifyingsig2"]
    verifyingsig2 = base64.b64decode(verifyingsig2)
    transactionfee = data["transactionfee"]
    sender = data["sender"]
    reciever = data["reciever"]
    vmtransactionnum = data["vmtransactionnum"]
    serverthingthing.getfilestufftransactionfromaltPC(price,txextra,transactionfee,sender,vmtransactionnum,reciever,verifyingsig1,verifyingsig2)
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/GETHARDDRIVEDATASTORAGE",methods=['GET'])
def getthestorage():
    datastorage = serverthingthing.getharddrivestorage()
    return jsonify({"Success":datastorage})
@app.route("/GETRAMGB",methods=['GET'])
def getramgb():
    ramgb = serverthingthing.getRAMonSERVER()
    return jsonify({"Success":ramgb})
@app.route("/GETVCPUS",methods=['GET'])
def getVCPUS():
    VCPUS = serverthingthing.getVCPUS()
    return jsonify({"Success":VCPUS})
@app.route("/GETDATATRANSFERPOWER",methods=['GET'])
def getDATATRANSFERPOWER():
    return jsonify({"Success":DATATRANSFERPOWER})
@app.route("/getthevalidatedIPADDRESS",methods=['POST'])
def loadtheIP():
  ip = request.remote_addr
  if ip == str(SELFVMTHINGLOADERIP):
   verifyingsig = data["verifyingsig"]
   truepowerthing = True
   IPaddress = data["IPAddress"]
   selfnum = 1
   try:
    with open("selfnum.txt","r") as file:
        selfnum = int(file.read())
   except:
    with open("selfnum.txt","w") as file:
        file.write(str(selfnum))
   if selfnum>1:
    VMDATALIST[str(VMDATALIST2["testythingy"+str(selfnum)]["String"])]["IP"] = IPaddress
    VMDATALIST[str(VMDATALIST2["testythingy"+str(selfnum)]["String"])]["Completed"] = True
   else:
    VMDATALIST[str(VMDATALIST2["testythingy"]["String"])]["IP"] = IPaddress
    VMDATALIST[str(VMDATALIST2["testythingy"]["String"])]["Completed"] = True
   selfnum+=1
   with open("selfnum.txt","w") as file:
       file.write(str(selfnum))
   createvmstuff("testythingy"+str(selfnum))
   return jsonify({"Success":"This worked"}),200
  else:
    return jsonify({"Error"})
@app.route("/gettheselfkey",methods=['GET'])
def gettheselfkey():
  ip = request.remote_addr
  if ip == str(SELFVMTHINGLOADERIP):
    selfkey = listofkeyeys[selfnum]["key"]
    return jsonify({"Success":selfkey})
@app.route("/getRAMGBPRICE",methods=['GET'])
def getRAMGB():
    return jsonify({"Success":RAMPRICEPERGB})
@app.route("/getVCPUPRICE",methods=['GET'])
def getVCPUPRICE():
    return jsonify({"Success":VCPUPRICE})
@app.route("/getDATATRANSFERGB",methods=['GET'])
def getDATATRANSFERGB():
    return jsonify({"Success":DATATRANSFERPRICEPERGB})
@app.route("/checkplaceinternetspeed",methods=['POST'])
def checkplaceinternetspeed():
   ip = request.remote_addr
   if ip == str(SELFVMTHINGLOADERIP):
    data=request.json
    if not "seedphrase" in data or not "internetspeed"in data:
        return jsonify({"Error":"You're missing something."}),403
    seedphrase = data["seedphrase"]
    vmname = VMDATALIST[seedphrase]["vmname"]
    internetspeed = int(data["internetspeed"]/(10**6))
    serverthingthing.CHECKTHINGSINTERNETSPEEDVALIDITY(vmname,internetspeed)
@app.route("/FindServer",methods=['POST'])
def FindServer():
    data = request.json
    wallet = data["Wallet"]
    server = serverthingthing.findserver(wallet)
    return {"Server":server}
@app.route("/createvm",methods=['POST'])
def createvm():
    data=request.json
    if "DATATRANSFERMB" not in data or "DATASTORAGEMB" not in data or "RAMMB" not in data or "VCPUS" not in data or "verifyingsig" not in data or "walletname" not in data:
        return jsonify({"Error":"You messed up."}),403
    DATATRANSFERMB = data["DATATRANSFERMB"]
    DATASTORAGEMB = data["DATASTORAGEMB"]
    RAMMB = data["RAMMB"]
    VCPUS = data["VCPUS"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    walletname = data["walletname"]
    vmname = serverthingthing.CREATEVMLOL(VCPUS,DATATRANSFERMB,RAMMB,DATASTORAGEMB,verifyingsig,walletname)
    return jsonify({"Success":vmname}),200
@app.route("/startvm",methods=['POST'])
def STARTVM2():
    data=request.json
    if "verifyingsig" not in data or "walletname" not in data or "vmname" not in data:
        return jsonify({"Error":"NO!"}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    walletname = data["walletname"]
    vmname = data["vmname"]
    serverthingthing.startVM(walletname,verifyingsig,vmname)
    return jsonify({"Success":"WE DID IT!@"}),200
Verifyingkey = load_pem_public_key(convertthething(str(public_pem)).encode('utf-8'),backend=default_backend)
print("VERIFYINGKEY: "+str(Verifyingkey))
print("public_pem:"+str(public_pem))
@app.route('/public-key')
def serve_public_key():
    return jsonify({'public_key': public_pem})
@app.route("/DELETEVM",methods=['POST'])
def DELETEVM():
    data=request.json
    if "verifyingsig" not in data or "walletname" not in data or "vmname" not in data:
        return jsonify({"Error":"NO!"}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    walletname = data["walletname"]
    vmname = data["vmname"]
    serverthingthing.DELETEVM(walletname,verifyingsig,vmname)
@app.route("/ADDFILETOVM",methods=['POST'])
def ADDFILETOVM():
    data=request.json
    if "verifyingsig" not in data or "walletname" not in data or "vmname" not in data or "filename" not in data:
        return jsonify({"Error":"There is something missing"}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    walletname = data["walletname"]
    vmname = data["vmname"]
    filename = data["filename"]
    serverthingthing.ADDFILETOVM(walletname,filename,vmname,verifyingsig)
@app.route("/ADDFILETOVM2",methods=['POST'])
def ADDFILETOVM2():
    data=request.json
    if "verifyingsig" not in data or "walletname" not in data or "vmname" not in data or "filename" not in data:
        return jsonify({"Error":"There is something missing"}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    walletname = data["walletname"]
    vmname = data["vmname"]
    filename = data["filename"]
    filedata = data["filedata"]
    serverthingthing.ADDFILETOVM2(walletname,filename,filedata,vmname,verifyingsig)
@app.route("/STOPVM",methods=['POST'])
def STOPVM():
    data=request.json
    if "verifyingsig" not in data or "vmname" not in data or not "walletname" in data:
        return jsonify({"Error":"There is something missing."}),403
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    vmname = data["vmname"]
    walletname = data["walletname"]
    serverthingthing.STOPVM(vmname,walletname,verifyingsig)
    return jsonify({"Success":"WE DID IT!"})
@app.route("/startvm",methods=['POST'])
def STARTVM():
    data = request.json
    if "verifyingsig" not in data or "walletname" not in data or "vmname" not in data:
        return jsonify({"Error":"There is something missing"}),403
    walletname = data["walletname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    vmname = data["vmname"]
    serverthingthing.startVM(walletname,verifyingsig,vmname)
    return jsonify({"Success":"WE DID IT!"})
@app.route("/executecommand",methods=['POST'])
def executecommand():
    data=request.json
    if "verifyingsig" not in data or "vmname" not in data or "command" not in data:
        return jsonify({"Error":"There is something missing."}),403
    vmname = data["vmname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    command = data["command"]
    serverthingthing.executecommandonVM(vmname,verifyingsig,command)
@app.route("/gethashstringplus",methods=['GET'])
def getthisone9now():
    hashstringthing = serverthingthing.gethashstringspecial()
    return jsonify({"Success":hashstringthing})
@app.route("/deletefilealt",methods=['POST'])
def deletefile():
    data=request.json
    if not "walletname" or not "verifyingsig" or not "filename" in data:
        return jsonify({"Error":"You're missing something."}),403
    walletname = data["walletname"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(verifyingsig)
    filename = data["filename"]
    serverthingthing.deletefile(walletname,verifyingsig,filename)
    return jsonify({"Success":"WE Deleted the file"})
@app.route("/getverifyingkeything",methods=['POST'])
def getthekey():
    data=request.json
    if "walletname" not in data:
        return jsonify({"Error":"WALLETNAME MISSING!"}),403
    walletname = data["walletname"]
    thekey = serverthingthing.getverificationkey(walletname)
    print(str(thekey))
    return jsonify({"Success":str(thekey)}),200
@app.route("/addIPtoVM",methods=['POST'])
def addIPtoVM():
    data = request.json
    if "IP" not in data:
        return jsonify({"Error":"Where is the IP"}),403
    VMDATALIST[listofkeyeys[selfnum]]["IP"] = data["IP"]
    return jsonify({"Success":"WE DID IT!"}),200
@app.route('/getOS',methods=['POST'])
def getOS():
    return jsonify({"Success":str(ISO)}),200
@app.route('/AddDataTransferstuff',methods=['POST'])
def adddatatransferstuff():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data or not "datatransferstuff" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    datatransferstuff = data["datatransferstuff"]
    serverthingthing.ADDINTERNETSPEEDTRANSFERDATATOVM(walletname,verifyingsig,vmname,datatransferstuff)
    return jsonify({"Success":"WE DID IT!"}),200

@app.route('/AddVMSTORAGEstuff',methods=['POST'])
def addvmstoragestuff():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data or not "vmstorage" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    vmstorage = data["vmstorage"]
    serverthingthing.ADDVMSTORAGE(walletname,verifyingsig,vmname,vmstorage)
    return jsonify({"Success":"WE DID IT!"}),200
@app.route('/AddVMRAMstuff',methods=['POST'])
def addvmramstuff():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data or not "vmstorage" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    vmstorage = data["vmstorage"]
    serverthingthing.ADDRAMTOVM(walletname,verifyingsig,vmname,vmstorage)
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/CHECKINTERNETTRANSFERAMOUNT",methods=['POST'])
def checkinternettransferamount():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    responseobject = serverthingthing.CHECKIFVMDATATRANSFERFULL(vmname,walletname,verifyingsig)
    return jsonify({"Success":str(responseobject)}),200
@app.route("/CHECKDATASTORAGEAMOUNT",methods=['POST'])
def checkdatastorageamount():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    responseobject = serverthingthing.CHECKIFVMDATASTORAGEFULL(vmname,walletname,verifyingsig)
    return jsonify({"Success":str(responseobject)}),200
@app.route("/CHECKVMRAMAMOUNT",methods=['POST'])
def checkvmramamount():
    data=request.json
    if not "walletname" in data or not "vmname" in data or not"verifyingsig" in data:
        return jsonify({"Error":"SOMETHINGS MISSING!"}),403
    walletname = data["walletname"]
    vmname = data["vmname"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    responseobject = serverthingthing.CHECKIFVMRAMFULL(vmname,walletname,verifyingsig)
    return jsonify({"Success":str(responseobject)}),200

dictionary = get_disk_info2()
for item in dictionary:
    harddrive = item
    
    datavailable = str(dictionary[item]["availabledata"])
    
    serverthingthing.addharddrive(harddrive)
    serverthingthing.setharddrivedata(harddrive, int(datavailable))


def on_focus_in2(event):
    if text_box2.get("1.0", tk.END).strip() == PlaceHolderText2:
        text_box2.delete("1.0", tk.END)  # Remove the placeholder text
        text_box2.config(fg='black')     # Set normal text color

def on_focus_out2(event):
    if text_box2.get("1.0", tk.END).strip() == "":
        text_box2.insert("1.0", PlaceHolderText2)  # Put the placeholder back
        text_box2.config(fg='grey')               # Set placeholder text color

def on_key_press2(event):
    current_text = text_box2.get("1.0", tk.END).strip()
    print("PlaceHolderText2: "+str(PlaceHolderText2))
    print("Current text: "+str(current_text))
    if current_text == PlaceHolderText2.strip():  # If placeholder is present
        text_box2.delete("1.0", tk.END)  # Remove the placeholder text
        text_box2.config(fg='black')     # Set normal text color
    else:
     print("What in the world.") 

IP = ""
Port = 0
Type = 0
server = ""
Variablelevel2 = 1
loadinputty = 0
loadinputty2 = 0
loadinputty3 = 0
loadinputty4 = 0
TABLEOFWEBSITESTOCHECK2 = {}
TheThingToCheck = 0
PlaceHolderText2 = "Enter the IP of the server you're connecting to."
def submit_text2():
    global Variablelevel2,httpthingy,SpecialDevice,SpecialDomain,inthing,inthinghash,loadthisloop,loadinputty,Variablelevel,VMLOADDRIVE,ISOFILE,SELFVMTHINGLOADERIP,TABLEOFWEBSITESTOCHECK2,PriceperGBperday,PriceperGBbutFIAT,RAMPRICEPERGB,RAMPRICEPERGBFIAT,DATATRANSFERPRICEPERGB,DATATRANSFERPRICEPERGBFIAT,VCPUPRICE,VCPUPRICEFIAT,allowedtostartpowerserver,DATATRANSFERPOWER,SPECIALPORT,seed_phrase, Variable1, Variable2, Variable3, Variable4, Variable5, PlaceHolderText2,Port,Type,server,loadinputty2,loadinputty3,loadinputty4,IP,TheThingToCheck

    user_text = text_box2.get("1.0", tk.END).strip()
    if user_text == PlaceHolderText2 or user_text == "":  # Check if the user input is valid
        print("No valid input submitted.")
    else:
        print(f"User entered: {user_text}")
        
        # Assign user input to the corresponding variable
        if Variablelevel2 == 1:
            IP = str(user_text)
            print("You've got to do something actually.")
            print("IP: "+str(IP))
            PlaceHolderText2 = "What is the port?"
            print("We're not working.")
            Variablelevel2 += 1
            
        elif Variablelevel2 == 2:
            Port = int(user_text)
            PlaceHolderText2 = "Well, 1. for special domain, 2. for regular. "
            Variablelevel2+=1

        elif Variablelevel2 == 3:
            Type = int(user_text)
            PlaceHolderText2 = "Well, 1. adding a server to the serverlist, and 2. for stopping it. "
            Variablelevel2+=1

        elif Variablelevel2 == 4:
            if loadinputty<=0:
             loadinputty = int(user_text)
             if loadinputty == 1:
              PlaceHolderText2 = "What is the server ip?"
              
             else:
              PlaceHolderText2 = "What is the amount of server coins you want the user to spend per gigabyte."
              Variablelevel2+=1
              root2.destroy()
            else:
            
             if loadinputty4 == 2 :
              Type2 = int(user_text)
              if Type2 == 2:

               newserver = server+str(port)
              else:
               newserver = server
              loadinputty = 0
              loadinputty2 = 0
              loadinputty3 = 0
              loadinputty4 = 0
              loadinputty5 = 0
              server = ""
              port = 0
              PlaceHolderText2 = "1. adding a server to the serverlist, and 2. for stopping it. "
              TABLEOFWEBSITESTOCHECK2[newserver] = {"Protocol":"","Port":0,"Type":0}
             elif loadinputty2<=0:
              server = user_text
              PlaceHolderText2 = "What is the server port?"
              loadinputty2 = 1
             elif loadinputty3<=0:
              port = int(user_text)
              PlaceHolderText2 = "1. for special domain, 2. for regular. "
              TABLEOFWEBSITESTOCHECK2[newserver]["Port"] = port

             elif loadinputty4<=0:
              protocol = user_text
              TABLEOFWEBSITESTOCHECK2[newserver]["Protocol"] = str(protocol)
              PlaceHolderText2 = "1. for special domain, 2. for regular. "
             elif loadinputty5<=0:
              specialdomain = int(user_text)
              TABLEOFWEBSITESTOCHECK2[newserver]["Type"] = specialdomain
             else:
              root2.quit()
              print("loadinputty: "+str(loadinputty))
              Variablelevel2+=1
              PlaceHolderText2 = "What is the amount of server coins you want the user to spend per gigabyte."


        elif Variablelevel == 5:
            seed_phrase = user_text
            PlaceHolderText = "What is the genesis password?"
            Variablelevel+=1
            
        elif Variablelevel == 6:
            inthing = user_text
            inthinghash = str(hashlib.sha256(inthing.encode('utf8')).hexdigest())
            if inthinghash == "c508c75cab978afb13baa0b2d9d42118dd4d40a233672510b7bfef3ad53573a8":
             allowedtostartpowerserver = True
            PlaceHolderText = "1. for stopping this and 2. for continuing this"
            Variablelevel+=1
        elif Variablelevel == 7:
            if loadinputty<=0:
             loadinputty = int(user_text)
             if loadinputty == 2:
              PlaceHolderText = "What is the Address of the website you are getting your data from?"
             else:
              PlaceHolderText = "What is the amount of server coins you want the user to spend per gigabyte."
              Variablelevel+=1
            else:
             if loadinputty == 2:
             
              newserver = user_text
              loadinputty = 0
              PlaceHolderText = "1. for stopping this and 2. for continuing this"
              TABLEOFWEBSITESTOCHECK.append(newserver)
             else:
              
              print("loadinputty: "+str(loadinputty))
              Variablelevel+=1
              PlaceHolderText = "What is the amount of server coins you want the user to spend per gigabyte."
        elif Variablelevel == 8:
            PriceperGBperday = float(user_text)
            
            PlaceHolderText = "What is the FIAT price of this thing? If there isn't one just type NONE."
            Variablelevel+=1
            
        elif Variablelevel == 9:
            if not user_text == "NONE":
             PriceperGBbutFIAT = float(user_text)
            else:
             PriceperGBbutFIAT = user_text
            PlaceHolderText = "What is the price of RAM per Gigabyte per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 10:
            RAMPRICEPERGB = float(user_text)
            
            PlaceHolderText = "What is the price of RAM per gigabyte per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 11:
            RAMPRICEPERGBFIAT = float(user_text)
            
            PlaceHolderText = "What is the price of DATA TRANSFER per Gigabyte per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 12:
            DATATRANSFERPRICEPERGBFIAT = float(user_text)
            
            PlaceHolderText = "What is the price of DATA TRANSFER per gigabyte per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 13:
            DATATRANSFERPRICEPERGB = float(user_text)
            
            PlaceHolderText = "What is the price of 1 VCPU per day on this server?"
            Variablelevel+=1
        elif Variablelevel == 14:
            VCPUPRICE = float(user_text)
            
            PlaceHolderText = "What is the price of 1 VCPU per day on this server in FIAT? Type -1 if none"
            Variablelevel+=1
        elif Variablelevel == 15:
            VCPUPRICEFIAT = float(user_text)
            
            PlaceHolderText = "What is the name of the drive that the VMs are stored in?"
            Variablelevel+=1
        elif Variablelevel == 16:
            VMLOADDRIVE = user_text
            
            PlaceHolderText = "What is the address of the ISO file?"
            Variablelevel+=1
            
        elif Variablelevel == 17:
            ISOFILE = user_text
            
            PlaceHolderText = "What is the IP address of the VM you use for the thing that allows the VMs this makes to get their IP?"
            Variablelevel+=1
        elif Variablelevel == 18:
            if PlaceHolderText == "The thing has finished. How'd you get here?":
                print("JUST QUIT NOW!")
                root.quit()
                print("YOU WERE SUPPOSED TO QUIT!")
            SELFVMTHINGLOADERIP = user_text
            
            PlaceHolderText = "1. for finishing the setup of this VM 2. for I don't want to do this "
            Variablelevel+=1
        elif Variablelevel == 19:
            TheThingToCheck = int(user_text)
            PlaceHolderText = "What Operating system are you hosting this on? Be specific."
            Variablelevel+=1
        elif Variablelevel == 20:
            ISO = user_text
            root2.quit()  # Exit the application after the fifth submission
            root2.destroy()
            print("YOU SHOULD'VE CLOSED THE TKINTER!")
        # Increment the level

        # Clear the text box and reset it with new placeholder text
        text_box2.delete("1.0", tk.END)
        text_box2.insert("1.0", PlaceHolderText2)
        text_box2.config(fg='grey')
        print("FIXED THIS!")
# Create the main window
with open("allowedtostartpowerserver.txt","w") as file:
    file.write(str(allowedtostartpowerserver))
if not allowedtostartpowerserver == True:
 with open("Powerserver2.txt","w") as file:
     file.write("How can these both activate?")
 root2 = tk.Tk()
 root2.title("Servercoin GUI part 1.")

# Make the window full screen
 root2.attributes('-fullscreen', True)

# Style the Textbox (make it more modern-looking)
 text_box2 = tk.Text(root2, height=10, fg='grey', bg='#f0f0f0', padx=10, pady=10, bd=2, relief="solid", font=("Arial", 18))
 text_box2.insert("1.0", PlaceHolderText2)  # Insert the initial placeholder text
 text_box2.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)  # Fill the entire available space

# Bind focus in/out events to manage the placeholder
 text_box2.bind("<FocusIn>", on_focus_in2)
 text_box2.bind("<FocusOut>", on_focus_out2)

# Bind key press event to remove placeholder when typing starts
 text_box2.bind("<Key>", on_key_press2)

# Style the Submit Button (bigger and light green, long width)
 submit_button2 = tk.Button(root2, text="Submit", command=submit_text2, bg='lightgreen', font=("Arial", 18, "bold"), padx=50, pady=20)
 submit_button2.pack(pady=20, fill=tk.X)  # Fill the width of the screen

# Start the Tkinter event loop
 root2.mainloop()
with open("SPECIALDOMAIN.txt","w") as file:
    file.write(str(SpecialDomain))
# After exiting the loop, we can print the collected variables if needed
print("Final Variables:")

with open("datatransferpower.txt","w") as file:
    file.write(str(DATATRANSFERPOWER))
print(httpthingy) 
print(SpecialDevice)
print(SpecialDomain)
print(TABLEOFWEBSITESTOCHECK)
PriceperGB = PriceperGBperday
PriceperGBperday = PriceperGBperday*(10**8)
PriceperGB = PriceperGBperday
RAMPRICEPERGB = RAMPRICEPERGB*(10**8)
RAMPRICEPERGB = math.floor(RAMPRICEPERGB)
DATATRANSFERPRICEPERGB=DATATRANSFERPRICEPERGB*(10**8)
DATATRANSFERPRICEPERGB=math.floor(DATATRANSFERPRICEPERGB)
VCPUPRICE = VCPUPRICE*(10**8)
VCPUPRICE = math.floor(VCPUPRICE)
if TheThingToCheck == 2:
    VCPUPRICE = 999999999999999999999999999999999999999999999999
    RAMPRICEGB = 9999999999999999999999999999999999999999999999999
    DATATRANSFERPRICEPERGB = 9999999999999999999999999999999999999
Variablelevel2 = 1



salt = "22".encode('utf-8')  
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(seed_phrase.encode())

private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),  
    ec.SECP256R1(),  
    backend=default_backend()
)

private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key3333333 = private_key3333.public_key()
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Print or save the private and public keys
serverlist = []
selfip = "192.168.56.1"
serverthingthing.listserver(selfip,"NONE",PriceperGB,public_key3333333,RAMPRICEPERGB,VCPUPRICE,DATATRANSFERPRICEPERGB,SPECIALPORT,"YES","YES",str(public_pem),"http://")

print("SERVERS OVER HERE: "+str(serverthingthing.getservers()))
if not allowedtostartpowerserver  == True:
    for item in TABLEOFWEBSITESTOCHECK2:
      if TABLEOFWEBSITESTOCHECK2[item]["Type"] == 2:
        serverlist.append(TABLEOFWEBSITESTOCHECK2[item]["Protocol"]+str(item)+str(TABLEOFWEBSITESTOCHECK2[item]["Port"]))
      else:
        serverlist.append(TABLEOFWEBSITESTOCHECK2[item]["Protocol"]+str(item))
   
    url = ""
    print("TYPE: "+str(Type))
    if Type == 2:
     url ="http://"+ IP + ":" + str(Port) + "/recieveservers"
     
    else:
     print("IP: "+str(IP))
     url = "https://"+IP+"/recieveservers"
    
    def addservertothat(server):
        if not server  in serverlist:
            serverlist.append(server)
    for item in serverlist:
        try:
         response = request.get(item)
        except:
            print("OH CRAP!!!!!!!!")
            lol=True
        for item in response:
            addservertothat(item)
    url2 = ""
    if Type == 2:
     url2 ="http://"+ IP + ":" + str(Port) + "/recieveservers"
    else:
     url2 = "https://"+IP+"/recieveservers"
    if Type == 2:
     fixurl = "http://"+ IP + ":" + str(Port) + "/doesitwork"
    else:
     fixurl = "https://"+IP+"/doesitwork"
    servers = []
    response = requests.get(fixurl)
    try:
     servers33 = requests.get(url)
     servers33=servers33.json()
     servers33 = servers33["Success"]
     servers = servers33
    except Exception as e:
    
        print("WE MESSED UP HARDDDDDDDD: "+str(e))
        lol=True
    print("servers2"+str(servers))
    for item in serverlist:
        urlthing = "http://"+serverlist[item]+"/recieveservers"
        try:
         serverthingpowerthing = requests.get(urlthing)
        
        except:
            lol=True
        superserverthing = serverthingpowerthing.json()

        for itemm in dict(superserverthing["Success"]):
            addservertothat(item)
    serverlistlist = {}
    serverhashlist = {}
    serverlistdoubleup={}
    def addtoserverhashlist(serverhash,serverthatsentit,item):
        if serverhash in serverhashlist:
            serverhashlist[serverhash]["Amount"]+=1
            serverhashlist[serverhash]["ServersThatGotIt"].append(serverthatsentit)
            serverlistdoubleup[serverhash]=item
            print(serverlistdoubleup[serverhash])
        else:
            serverhashlist[serverhash] = {"Amount":1,"ServersThatGotIt":[]}
            serverhashlist[serverhash]["ServersThatGotIt"].append(serverthatsentit)
            serverlistdoubleup[serverhash]=item

    it = 0
    deletetheseservers = []
    for item in servers:
       
       try:
        print("servers:"+str(servers[item]))
        responsething = requests.get("http://"+servers[item]+"/recieveservers")
        responsething2 = requests.get("http://"+servers[item]+"/recieveservers2")
        
        responsething=responsething.json()
        print("HOW'D WE GET HERE???")
        responsething2 = responsething2.json()
        responsething2 = responsething2["Success"]
        print("can we get here?")
        print("Responsething:"+str(responsething2))
        servers2 = dict(responsething2)
        print
        serverlistlist[item] = {"Data":responsething["Success"],"Server":servers[item],"NEWDATA":responsething2}
        print("serverlistlist:"+str(serverlistlist))
        print("YES!")
        it+=1

       except Exception as E:
           print("error: "+str(E))
           deletetheseservers.append(item)
           lol=True
       print(servers2[servers[item]])
       load_pem_public_key(convertthething(servers2[servers[item]]["verifyingkey"]).encode('utf-8'),backend=default_backend)
    for item in servers:
                               print("Servers: "+str(servers))
                               try:

                                serverthingthing.listserver(servers2[item]["server"],servers2[item]["altserver"],servers2[item]["Fileprice"],load_pem_public_key(convertthething(servers2[item]["verifyingkey"]).encode('utf-8'),backend=default_backend),servers2[item]["RAMGBPRICE"],servers2[item]["VCPUPRICE"],servers2[item]["DATATRANSFERGB"],servers2[item]["portthing"],servers2[item]["MINERCHECK"],servers2[item]["NODECHECK"],servers2[item]["verifyingkey"],servers2[item]["PROTOCOL"])
                               except Exception as e:
                                   
                                   print("Ehhhhh it was just THAT server. "+str(e))
                               try:
                                serverthingthing.addtimeaddedtimetoserver(servers[item]["server"],servers[item]["timeadded"])
                               except Exception as e:
                                   print("OH NO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"+str(e))
    for item in deletetheseservers:
        del servers[item]
    print("Serverlistlist: "+str(serverlistlist))
    table_string=""
    for item in serverlistlist:
      for itemm in serverlistlist[item]["Data"]:
        table_string = table_string+str(serverlistlist[item]["Data"][itemm])
      hashthing = hashlib.sha256(table_string.encode('utf8')).hexdigest()
      addtoserverhashlist(hashthing,serverlistlist[item]["Server"],item)
    TOTALPOWERVALUE = True
    FIRSTWAVE = True
    HashList = {}
    def addhashthingtohashlist(hasht,server):
      try:
        if not hasht in HashList:
            HashList[hasht] = {"Amount":1,"Serverswithhash":[]}
            HashList[hasht]["Serverswithhash"].append(server)
            print("HashList2: "+str(HashList))
        else:
            HashList[hasht]["Amount"]+=1
            HashList[hasht]["Serverswithhash"].append(server)
            print("HashList2: "+str(HashList))
      except Exception as e:
          print("Our mission failed because: "+str(e))

    BLOCKSWENTTHROUGH = 0
    VKEYPLUSWALLETS = 0
    BLOCKLISTTHING = {}
    serverthingthing = serverthing()
    timestamplist = {}
    trueserverlist = {}
    def addnumtotimestamplist(timestamp):
        if timestamp not in timestamplist:
            timestamplist[timestamp] = {"Amount":1}
        else:
            timestamplist[timestamp]["Amount"]+=1
    print(serverhashlist)
     
    max_hash_key = max(serverhashlist, key=lambda x: serverhashlist[x]['Amount'])
    print("Serverlistdoubleup:"+str(serverlistdoubleup))
    print(serverlistdoubleup[max_hash_key])
    trueserverlist = serverlistlist[serverlistdoubleup[max_hash_key]]
    print("trueserverlist: "+str(trueserverlist))
    ID =0 
    for item in trueserverlist:
            try:
             requesttything = requests.get(trueserverlist["NEWDATA"][trueserverlist["Data"][str(ID)]]["PROTOCOL"]+str(trueserverlist["Data"][str(ID)])+"/getblockchainstarttime")
             if requesttything.status_code == 200:
                requesttything = requesttything.json()
                addnumtotimestamplist(requesttything["Success"])
                print("NUMTIMESTAMP: "+str(timestamplist))
             else:
                 print("Oh.")
            except:
                lol=True
            ID+=1
            print("YEEEESSSSSS")
            

 
    while TOTALPOWERVALUE == True:
        doomblocks = 0
        blockreward = 0
        print("TOTALPOWERVALUE: "+str(TOTALPOWERVALUE))
        print("POWER")
        if TOTALPOWERVALUE == False:
                break
        if FIRSTWAVE == True:
            ID =0 
            print("TOTALPOWERVALUE: "+str(TOTALPOWERVALUE))
            
            for item in trueserverlist["Data"]:
                try:
                 print("SERVERLIST:"+str(trueserverlist))
                 print("SERVERLISTID: "+str(trueserverlist["Data"]))
                 requestthing = requests.get(trueserverlist["NEWDATA"][trueserverlist["Data"][str(ID)]]["PROTOCOL"]+str(trueserverlist["Data"][str(ID)])+"/gethashstringplus")
                 if requestthing.status_code == 200:
                    requestthing = requestthing.json()
                    addhashthingtohashlist(requestthing["Success"],trueserverlist["Data"][str(ID)])
                    print("HashList33"+str(HashList))
                 else:
                     print("Status code: "+str(requestthing.status_code))
                except Exception as e:
                    print("Mission Failed because: "+str(e))
                    lol=True
                ID+=1
            print("HashList"+str(HashList))
            print("TimeStampList: "+str(timestamplist))
            hashthingthingthing = max(HashList,key=lambda x: HashList[x]['Amount'])
            timestartdate = 1751892642
            with open("timestartdate.txt","w") as file:
                file.write(str(timestartdate))
            serveramount = len(HashList[hashthingthingthing]["Serverswithhash"])
           
            HASHSTRINGFORHASHCHECKTHING = ""
            hashstringlist = []
            trueproof = False
            urltosendto = ""
            urltosendto2 = ""
            POWERVAL = True
            if POWERVAL == False:
                  TOTALPOWERVALUE = False
                  print("ITS OVER")
                  break
            while trueproof == False:
              if POWERVAL == False:
                  TOTALPOWERVALUE = False
                  print("ITS OVER")
                  break
                  break
                  break
                  break
              HASHSTRINGFORHASHCHECKTHING = ""

              blocklistthingy = {}
              HASHLEN = 0
              randomserver = random.randint(0,serveramount-1)
              try:
               HASHLEN = len(HashList[hashthingthingthing]["Serverswithhash"])
              except:
                  print("Umm wut")
                  HASHLEN = int(serveramount)
              print("HASH LENGTH:"+str(HASHLEN))
              print("STEP 11")
              if HASHLEN == 0:
                  print("WHAHTHTHTHHTHTHTHE HECK HAPPENDNENN")
                  POWERVAL = False
                  break

              if randomserver<=HASHLEN and urltosendto == "":
               print("SERVER: "+str(HashList[hashthingthingthing]["Serverswithhash"]))
               urltosendto = HashList[hashthingthingthing]["Serverswithhash"][int(randomserver)]
               urltosendto2 = trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getalltheblocks"
               print("URLTOSENDTO2: "+str(urltosendto2))
              else:
                  print("FAIL!")
                  POWERVAL = False
              lol = False
              sql_file_path = "output.sql"
              new_database_path = "blocklist.db"
              try:
                if lol == False:
                  respondtomeplz = requests.get(urltosendto2)
                  with open(sql_file_path, 'wb') as file:
                   file.write(respondtomeplz.content)
                  conn = sqlite3.connect("blocklist.db")
                  cur = conn.cursor()
                  cur.execute("DROP TABLE IF EXISTS kv_store")
                  conn.commit()
                  conn.close()
                  import_sql_file(sql_file_path, new_database_path)
                print("LOADED!")
               

              except Exception as e:
                  print("ERROR:"+str(e))
                  print("HAHAHAHHAHAAHAHAHHHAHA!!!!!!!!!!!")
                  POWERVAL = False
              print("STEP 12")
              if TOTALPOWERVALUE == False:
                  print("ITS ALLLLLLLLL OVER")
                  break
              urltosendto = HashList[hashthingthingthing]["Serverswithhash"][int(randomserver)]
              urltosendto244 = trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getblocknum"
              cleaneditems = []
              for item in blocklistthingy.keys():
               BLOCKDATATYPE = "Blockdata"
               try:
                blocklistthingy[item][BLOCKDATATYPE]
               except:
                BLOCKDATATYPE = "BlockData"
               if "STOP" in blocklistthingy[item][BLOCKDATATYPE]:
                 cleaneditems.append(str(item))
              for item in cleaneditems:
                BLOCKDATATYPE = "Blockdata"
                try:
                 blocklistthingy[item][BLOCKDATATYPE]
                except:
                 BLOCKDATATYPE = "BlockData"
                del blocklistthingy[item][BLOCKDATATYPE]["STOP"]
              sql_file_path = "output.sql"
              new_database_path = "blocklist.db"
              blocklistthingy = DiskBackedDict("blocklist.db")
              blocklenthing = len(blocklistthingy.keys())
              maxblocknum = time.time()-timestartdate
              numberstring = "0123456789"
              blockstoremove = []
              for item in blocklistthingy.keys():
                  keys_to_keep = {'BlockData', 'Blockhash',"Dateadded","FirstSender"}  # Define keys that should be kept
                  DICTX = {}
                  try:
                      DICTX["BlockData"] = blocklistthingy[item]["BlockData"]
                      DICTX["Blockhash"] = blocklistthingy[item]["Blockhash"]
                      DICTX["Dateadded"] = blocklistthingy[item]["Dateadded"]
                      DICTX["FirstSender"] = blocklistthingy[item]["FirstSender"]
                  except:
                      blockstoremove.append(str(item))

                  keys_to_remove = [key for key in blocklistthingy[item].keys() if key not in keys_to_keep]
                  for key in keys_to_remove:
                      blockstoremove.append(str(item))
                      break
              try:
                  responsepower = requests.get(urltosendto244)
                  responsepower = responsepower.content
                  print("responsepower.content: "+str(responsepower))
                  responsepower = str(responsepower)
                  newpowerresponse = '' 
                  for letter in responsepower:
                    if letter in numberstring:
                      newpowerresponse=newpowerresponse+str(letter)
                  print("newpowerresponse: "+str(newpowerresponse))
              except Exception as e:
                  print("ERROROROROR: "+str(e))
              if blocklistthingy["0"]["Blockhash"] == blocklistthingy["1"]["Blockhash"]:
                      print("What happened here?????")
                      with open("Crap.txt","w") as file:
                       file.write("Why did this happen...")
              trueblocknum = int(maxblocknum)
              maxblocknum = maxblocknum/9+1
              if len(blocklistthingy.keys())>maxblocknum:
                  blocklistthingy = {}
                  del HashList[hashthingthingthing]["Serverswithhash"]
              timelen = 0
              print("blocklenthing: "+str(blocklenthing))
              blocknum = 0
              HASHTOACCESS = {}
              numthingmax = 1
              for item in blocklistthingy.keys():
                   HASHTOACCESS[numthingmax] = min(blocklistthingy.keys(), key=lambda x: float(blocklistthingy[x]["Dateadded"]))
                   numthingmax+=1
              for i in range(len(blocklistthingy.keys())):
                 BLOCKACCESSTHING = str(i)
                 hashstringlist.append(blocklistthingy[BLOCKACCESSTHING]["Blockhash"])
                 timelen+=1
                 try:
                  print("Thingy: "+str(blocklistthingy[blocknum]))
                 except:
                  print("That block is missing, if this isn't block 8 watch out!")
                 HASHSTRINGFORHASHCHECKTHING =HASHSTRINGFORHASHCHECKTHING+blocklistthingy[blocknum]["Blockhash"]
                 print("POWERHASH: "+str(blocklistthingy[BLOCKACCESSTHING]["Blockhash"]))
                 blocknum+=1
              print("timelen: "+str(timelen))
              print("STRINGLEN: "+str(HASHSTRINGFORHASHCHECKTHING))
              with open("CHECKTHISOUTRIGHTNOW.txt","w") as file:
                  file.write(str(HASHSTRINGFORHASHCHECKTHING))
              newblockstring0 = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getnewblockstring0")
              hashthingpowerforever = hashlib.sha256(HASHSTRINGFORHASHCHECKTHING.encode('utf8')).hexdigest()
              if not len(hashthingthingthing) == 64:
                  hashthingthingthing = hashlib.sha256(hashthingthingthing.encode('utf8')).hexdigest()
              if HASHSTRINGFORHASHCHECKTHING == newblockstring0:
                  print("so what...")
              BLOCKDEVICE = {}
              print("STEP 13")
              print("HASHTHINGPOWERFOREVER:"+str(hashthingpowerforever))
              print("HASHTHINGTHINGTHING"+str(hashthingthingthing))
              hashpost = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/gethashstringplus")
              hashpost = hashpost.json()
              hashpost = hashpost["Success"]
              LOADABLEKEY = False
              superservers=requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/recieveservers2")
              with open("Superservers.txt","w") as file:
                  file.write(str(superservers))
              superservers = superservers.json()
              superservers = superservers["Success"]
              with open("hashpost.txt",
                        "w") as file:
                  file.write(str(hashpost))
              with open("HASHCHECKTHING.txt","w") as file:
                  file.write(str(HASHSTRINGFORHASHCHECKTHING))
              if not HASHSTRINGFORHASHCHECKTHING == hashpost:
                  print("Oh, it all makes sense now.")
              response = requests.get("https://servercoinofficial.pythonanywhere.com/public-key")
              public_key_pem = response.json()["public_key"]
              if not hashthingpowerforever == hashthingthingthing:
                  print("THIS IS WHY!!!!!!")
                  print("HASHTHINGPOWERFOREVER: "+str(hashthingpowerforever))
                  print("HASHTHINGTHINGTHING: "+str(hashthingthingthing))
                  for item in HashList[hashthingthingthing]["Serverswithhash"]:
                      if item == urltosendto:
                          del item
         
              else:
               totalitems = 0
               PROOFOFHAPPEN = True
               PROOFOFHAPPEN2 = True
               HASHTOACCESS = {}
               numthingmax = 1
               for item in blocklistthingy.keys():
                   HASHTOACCESS[numthingmax] = min(blocklistthingy.keys(), key=lambda x: float(blocklistthingy[x]["Dateadded"]))
                   numthingmax+=1
               loadedupthisround = False
               loadedup = False
               for i in range(len(blocklistthingy.keys())):
                  loadedupthisround = False
                  if blocklistthingy["0"]["Blockhash"] == blocklistthingy["1"]["Blockhash"]:
                      print("What happened here?????")
                      with open("Crap.txt","w") as file:
                          file.write("Why did this happen...")
                  if loadedup == False:
                      loadedupthisround = True
                      loadedup = True
                  blockstring = ""
                  print("STEP 14")
                  print("DATAINBLOCK: "+str(blocklistthingy[item]))
                  BLOCKDEVICE = blocklistthingy[item]
                  BLOCKACCESSTHING = str(i)
                  print("BLOCKACCESSTHING: "+str(BLOCKACCESSTHING))
                  try:
                      dicty = blocklistthingy[item]["Blockdata"]
                      BLOCKDATATYPE = "Blockdata"
                  except:
                      print("WRONG TYPE!!!!")
                  try:
                      dicty = blocklistthingy[item]["BlockData"]
                      BLOCKDATATYPE = "BlockData"
                  except:
                      print("WRONG TYPE!!!!")
                

                  
                  
                  try:
                    DICTX = blocklistthingy[BLOCKACCESSTHING]["Blockdata"]
                    BLOCKDATATYPE = "Blockdata"
                  except:
                    BLOCKDATATYPE = "BlockData"
                  if not BLOCKDATATYPE in blocklistthingy[BLOCKACCESSTHING]:
                      print("WHAT????: "+str(blocklistthingy[BLOCKACCESSTHING]))
                  for itemm in blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE]:
                     
                     print("Item: "+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE]))
                     if blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Type"] == 1:
                      blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Sender"]
                      blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Reciever"]
                      blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["amountofcoins"])
                      blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["transactionfee"])
                      blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig"]
                      blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["txextra"]
                     elif blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Type"] == 2:
                          blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Sender"]
                          blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Reciever"]
                          blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["transactionfee"])
                          blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig1"]
                          blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig2"]
                          blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["filehash"]
                          blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["fileprice"])
                          blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["daysoflasting"])
                          blockstring = blockstring+str(blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["filesize"])
                     elif blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Type"] == 3:
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Sender"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Reciever"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["transactionfee"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig1"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig2"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["filepricething"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["daysoflasting"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["filespace"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["pendingtransactionnum"]
                     elif blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Type"] == 4:
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Sender"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["Reciever"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["transactionfee"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig1"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["verifyingsig2"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["amountofcoins"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["txextra"]
                         blockstring = blockstring+blocklistthingy[BLOCKACCESSTHING][BLOCKDATATYPE][itemm]["vmtransactionnum"]
                  if loadedupthisround == True:
            
                   with open("Block0part1.txt","w") as file:
                      file.write(str(blockstring))
                  blockstring+=str(blocklistthingy[BLOCKACCESSTHING]["FirstSender"])
                  if loadedupthisround == True:
                   with open("Block0part2.txt","w") as file:
                      file.write(str(blockstring))
                  data = {"Wallet":blocklistthingy[BLOCKACCESSTHING]["FirstSender"]}
                  server = requests.post(str(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"])+urltosendto+"/FindServer",json=data)
                  server = server.json()
                  server = server["Server"]
                  timeaddedthing = superservers[server]["timeadded"]
                  
                  sTF = int(timestartdate)
                  sTF+=int(i)*603
                  with open("i.txt","w") as file:
                   file.write(str(i))
                  if loadedupthisround == True:
                   with open("MaybeHer1.txt","w") as file:
                      file.write(str(sTF))
                  sTF-=timeaddedthing
                  if loadedupthisround == True:
                   with open("MaybeHer2.txt","w") as file:
                      file.write(str(sTF))
                   with open("TimeAdded.txt","w") as file:
                      file.write(str(timeaddedthing))
                  
                  signature = base64.b64decode(blocklistthingy[BLOCKACCESSTHING]["Signature"])
                  message = blocklistthingy[BLOCKACCESSTHING]["FirstSender"]
                  message = message.encode("utf-8")
                  

                  public_keyoftheserver = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                  try:
                                     public_keyoftheserver.verify(
                                      signature,
                                      message,
                                      ec.ECDSA(hashes.SHA256())

                                     )

                  except:
                   PROOFOFHAPPEN = False
                   print("This is why")
                  stuffpower = str(i)+str(server)
                  if loadedupthisround == True:
                   with open("MaybeHer7.txt","w") as file:
                      file.write(str(stuffpower))
                  eothingtoadd2 = hashlib.sha256(stuffpower.encode('utf8')).hexdigest()
                  if loadedupthisround == True:
                   with open("MaybeHer6.txt","w") as file:
                      file.write(str(eothingtoadd2))
                  SEALDEAL = int(str(eothingtoadd2),16)
                  if loadedupthisround == True:
                   with open("MaybeHer5.txt","w") as file:
                      file.write(str(SEALDEAL))
                  SEALDEAL = SEALDEAL%7
                  if loadedupthisround == True:
                   with open("MaybeHer4.txt","w") as file:
                      file.write(str(SEALDEAL))
                  numthing = sTF*(SEALDEAL+1)
                  if loadedupthisround == True:
                   with open("MaybeHer3.txt","w") as file:
                      file.write(str(numthing))
                  
                  blockstring+=str(numthing)
                  if loadedupthisround == True:
                   with open("Block0part3.txt","w") as file:
                      file.write(str(blockstring))
                  blockhashthingything = ''
                  blockhashthingything = hashlib.sha256(blockstring.encode('utf8')).hexdigest()
                  
                  if not blocklistthingy[BLOCKACCESSTHING]["Blockhash"] == blockhashthingything:
                      PROOFOFHAPPEN = False
                      print("Totalitemnum: "+str(totalitems))
                      print("Totalitems: "+str(hashstringlist[totalitems]))
                      with open("TheBlockHere.txt","w") as file:
                          file.write(str(blocklistthingy[BLOCKACCESSTHING]["Blockhash"]))
                      print("Blockstring: "+str(blockstring))
                      with open("TheBlockString.txt","w") as file:
                          file.write(str(blockstring))
                      print("I: "+str(i))
                      totalitems = 0
                      print("hashstringlist")
                      print("Ohhhhhhhhhhhhhhhhhhh")
                      try:
                       if HashList[hashthingthingthing]["Serverswithhash"][randomserver]:
                          del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                       break
                      except:
                          print("It doesn't even exist anymore.")
                          POWERVAL = False
                          break
                  
                  else:
                      totalitems+=1
               FINISHEDTHESTUFF4EVER = True
               print("STEP 15")
               print("PROOFOFHAPPEN: "+str(PROOFOFHAPPEN))
               with open ("PROOFOFHAPPEN.txt","w") as file:
                   file.write(str(PROOFOFHAPPEN))
               if PROOFOFHAPPEN == False:
                   POWERVAL = False
               if PROOFOFHAPPEN == True:
                   DICTIONARY = {}
                   print("Step 1")
                   verifyingkeydatalist = {}
                   verifyingkeyhashdatalist  ={}
                   keydatanumber = 1
                   for item in servers:
                                if keydatanumber>5:
                                    break
                                urltosendto = trueserverlist["Data"][str(item)]
                                try:
                                 verifyingkeys22 = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getalltheverifyingkeys")
                                 verifyingkeys22 = verifyingkeys22.json()
                                 print("VERIFYINGKEYS: "+str(verifyingkeys22))
                                 verifyingkeys22 = verifyingkeys22["Success"]
                                 hashthis = ""
                                 for item in verifyingkeys22:
                                    hashthis = hashthis+str(verifyingkeys22[item]["walletname"])
                                    hashthis = hashthis+str(verifyingkeys22[item]["verifyingkey"])
                                 hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                 if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                 else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                 verifyingkeydatalist[hashthis] = verifyingkeys22
                                 keydatanumber+=1
                                except:
                                    print("Can't Do")
                   highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
                   Datathing = verifyingkeydatalist[str(highest_item)]
                   EASYTOUSEDATATHING = {}
                   WALLETVALUES = {}
                   for item in Datathing:
                       
                       Walletindata = Datathing[item]["walletname"]
                       Verifyingkey = Datathing[item]["verifyingkey"]
                       print("WALLET: "+str(Walletindata))
                       EASYTOUSEDATATHING[Walletindata] = {"Verifyingkey":load_pem_public_key(convertthething(Verifyingkey).encode('utf-8'),default_backend()),"Verifyingkeysummoningthing":Verifyingkey}
                       WALLETVALUES[Walletindata] = {"Coins":0,"txextras":{}}
                   print("Step 3")
                   PROOFOFHAPPEN3 = True
                  
                   COMBINETHEMBOTHFOREVERLOL = {}
                   itemswentthrough = 0
                   blockreward = 420000*(10**8)
                   blocksuntildoom = 5
                   
                   print("BLOCKACTIVATE: "+str(BLOCKDEVICE))
                   loadedthatalready = False
                   for item in blocklistthingy.keys():
                       print("Step 4")
                       
                       print("BLOCKSTUFF: "+str(blocklistthingy[item]))
                       transactionfeetotal = 0
                       if PROOFOFHAPPEN3 == False:
                           break
                       BLOCKDATATYPE = ""
                       try:
                        dicty = blocklistthingy[item]["Blockdata"]
                        BLOCKDATATYPE = "Blockdata"
                       except:
                        print("WRONG TYPE!!!!")
                       try:
                        dicty = blocklistthingy[item]["BlockData"]
                        BLOCKDATATYPE = "BlockData"
                       except:
                        print("WRONG TYPE!!!!")
                       print("Step 4.5")
                       if "STOP" in blocklistthingy[item][BLOCKDATATYPE]:
                           blocklistthingy[item][BLOCKDATATYPE] = {}
                           print("Removing data from useless tool.")
                           print("Data: "+str(blocklistthingy[item][BLOCKDATATYPE]))
                       for itemm in blocklistthingy[item][BLOCKDATATYPE]:
                          print("Step 5")
                          if loadedthatalready == False:
                           with open("OGtxextra.txt","w") as file:
                              file.write(str(item)+": "+str(blocklistthingy[item][BLOCKDATATYPE][itemm]))
                              loadedthatalready = True
                          if not "STOP" in blocklistthingy[item][BLOCKDATATYPE]:
                           print("THE ITEM: "+str(blocklistthingy[item][BLOCKDATATYPE][itemm]))
                           if blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"] == 1:
                            print("Yes")
                            keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig","transactionfee","lol"}  # Define keys that should be kept
                          
                            keys_to_remove = [key for key in blocklistthingy[item][BLOCKDATATYPE][itemm].keys() if key not in keys_to_keep]
                            for key in keys_to_remove:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                with open("here.txt","w") as file:
                                    file.write("here")
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                            try:
                             DICTX = {}
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig"]
                             DICTX["YES"]=blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                            except:
                                truethingthing2 = False
                                with open("here.txt","w") as file:
                                    file.write("here 2")
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                  
                            blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]=remove_sql(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])

                           
                            if blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"]:
                             print("FOUND IT")
                            if WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"] >= (blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"] + blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]) and not blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"] and blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]%1==0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]%1==0 and len(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])==10 and blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]>0:
                             print("YEA")
                             print(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])
                             publickeything = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Verifyingkey"]
                             print(publickeything)
                             print(blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig"])
                             signature =  blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig"]
                             try:
                                           signature = base64.b64decode(signature)
                             except Exception as e:
                                      print("Error: "+str(e))
                             transactionfeedevice = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                             if str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]).find(".") == -1:
                                transactionfeedevice = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])+".0"
                             messagething = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]) + str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]) + str(blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]) + str(transactionfeedevice) + str(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])
                             print(signature)
                             message = messagething.encode('utf-8')
                             print(messagething)
                             try:
                              publickeything.verify(
                               signature,
                               message,
                               ec.ECDSA(hashes.SHA256())
                              )
                           
                             except Exception as e:
                                with open("FailedTransaction.txt","w") as file:
                                    file.write("Transaction Failed.")
                                truethingthing2 = False
                                with open("here.txt","w") as file:
                                    file.write("here 3")
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                             validornot = True
                             try:
                              int(blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"])
                              int(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                             except:
                                with open("here.txt","w") as file:
                                    file.write("here 4")
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"] += -(blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"] + blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"][blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]] = {"yes"}
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Coins"] += (blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"])

                             transactionfeetotal+=blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                           elif blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"] == 2:
                            keys_to_keep = {'Type', 'fileprice',"Sender","Reciever","txextra","verifyingsig1","transactionfee","filesize","txextra2","verifyingsig2","filehash","filesize","daysoflasting","lol"}  # Define keys that should be kept
                            keys_to_remove = [key for key in blocklistthingy[item][BLOCKDATATYPE][itemm].keys() if key not in keys_to_keep]
                            for key in keys_to_remove:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                           
                           
                            try:
                             DICTX = {}
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra2"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["filesize"]
                             DICTX["YES"] =blocklistthingy[item][BLOCKDATATYPE][itemm]["filehash"]
                            except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                              
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                            blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]= remove_sql(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])
                            blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra2"]= remove_sql(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra2"])

                            print("Started Up")
                            try:
                             int( blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                             int( blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"])
                            except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                           
                         
         
                            verifythis = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filesize"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["daysoflasting"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filehash"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                            print("VERIFYTHISPART2: "+str(verifythis))
                            verifythis2 = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra2"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])+".0"         
                            print("Part2: "+str(verifythis2))
                            signature = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                            try:
                                           signature = base64.b64decode(signature)
                            except Exception as e:
                                      print("Error: "+str(e))
                            signature2 = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                            try:
                                           signature2 = base64.b64decode(signature2)
                            except Exception as e:
                                      print("Error: "+str(e))
                            publickeything = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Verifyingkey"]
                            publickeything2 = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Verifyingkey"]
                            TRUEPOWERTHING = False
                            TRUEPOWERTHING2 = False
                            if not blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]+blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]< WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"] or blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"] or blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["txextras"] or not len(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra2"]) == 10 or not blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]%1==0 or not blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]%1 == 0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]>0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]>0:
                             TRUEPOWERTHING = False
                             TRUEPOWERTHING2 = False
            
                           
           
                            print("Reasons for failure:")
    
                            if  (blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"] + blocklistthingy[item]["Blockdata"][itemm]["transactionfee"]) > WALLETVALUES[blocklistthingy[item]["Blockdata"][itemm]["Sender"]]["Coins"]:
                              print("Insufficient coins in Sender's wallet")

                            if blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in \
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"]:
                             print("txextra already exists in Sender's txextras")

                            if blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in \
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["txextras"]:
                             print("txextra already exists in Receiver's txextras")

                            if not len(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]) == 10:
                             print("Invalid length of txextra")

                            if not blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"] % 1 == 0:
                             print("Transaction fee is not a whole number")

                            if not blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"] % 1 == 0 or \
                             blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"] <= 0 or \
                             blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"] <= 0:
                             print("Invalid file price or transaction fee")

                           
                            try:
                             publickeything.verify(
                              signature,
                              verifythis2.encode('utf-8'),
                              ec.ECDSA(hashes.SHA256())
                             )
                             TRUEPOWERTHING = True
                            except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                            try:
                             publickeything2.verify(
                              signature2,
                              verifythis.encode('utf-8'),
                              ec.ECDSA(hashes.SHA256())
                             )
                             TRUEPOWERTHING2 = True
         
                            except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                            if TRUEPOWERTHING == True and TRUEPOWERTHING2 == True:
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"]+=-(blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]+blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"][blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]] = "yes"
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["txextras"][blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]] = "yes"
                             WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Coins"]+=blocklistthingy[item][BLOCKDATATYPE][itemm]["fileprice"]
                             
                             print("IT IS DONE.")
                            else:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                           elif blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"] == 3:
                             print("COME")
        

                             try:
                              int(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                              int(blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"])
                             except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                             keys_to_keep = {'Type', 'filepricething',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","daysoflasting","filespace","pendingtransactionnum","lol"}  # Define keys that should be kept
        
                             truethough = True
                             keys_to_remove = [key for key in blocklistthingy[item][BLOCKDATATYPE][itemm].keys() if key not in keys_to_keep]
                             for key in keys_to_remove:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                             try:
                              DICTX = {}
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                              DICTX["YES"] =  blocklistthingy[item][BLOCKDATATYPE][itemm]["filespace"]
                              DICTX["YES"] =  blocklistthingy[item][BLOCKDATATYPE][itemm]["daysoflasting"]
                              DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["pendingtransactionnum"]
                             except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                             blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]= remove_sql(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])
                          
                             verifyingkey1 = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Verifyingkey"]
                             verifyingkey2 = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Verifyingkey"]
                             verifyingsig1 = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                             try:
                                           verifyingsig1 = base64.b64decode(verifyingsig1)
                             except Exception as e:
                                      print("Error: "+str(e))
                             verifyingsig2 = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                             try:
                                           verifyingsig2 = base64.b64decode(verifyingsig2)
                             except Exception as e:
                                      print("Error: "+str(e))
                             verifythis1 = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["pendingtransactionnum"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filespace"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["daysoflasting"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])

                             try:
                              verifyingkey1.verify(
                               verifyingsig1,
                               verifythis1.encode('utf-8'),
                               ec.ECDSA(hashes.SHA256())
                              )
                             except:
                              truethough = False
                              print("MESSUPREASON: 2")
                             verifythis2 = str(blocklistthingy[item][BLOCKDATATYPE][itemm]["pendingtransactionnum"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filespace"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["daysoflasting"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"])+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"])+blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]+str(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])

                             try:
                              verifyingkey2.verify(
                               verifyingsig2,
                               verifythis2.encode('utf-8'),
                               ec.ECDSA(hashes.SHA256())
                             )
                             except:
                              print("MESSUPREASON: 3")
                              truethough = False
                             if truethough == True and WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"]>=(blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]+blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]) and not blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"] and not blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"] in WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["txextras"] and blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]%1==0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]%1==0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]>0 and blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]>0:
                              WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Coins"]+=-(blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]+blocklistthingy[item]["Blockdata"][itemm]["transactionfee"])
                              WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["txextras"][blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]]= "yes"
                              WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["txextras"][blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]]= "yes"
                              WALLETVALUES[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Coins"]+=blocklistthingy[item][BLOCKDATATYPE][itemm]["filepricething"]
                              transactionfeetotal+=blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                             else:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                           elif blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"] == 4:
                            print("Come")

                            keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","vmtransactionnum","lol"}  # Define keys that should be kept
                            truepower1 = True
                            try:
                             int(blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"])
                             int(blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"])
                            except:
                                truethingthing2 = False
                                PROOFOFHAPPEN3 = False
                                blockreward = 420000*(10**8)
                                blocksuntildoom = 5
                                itemswentthrough = 0
                                del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                break 
                            keys_to_remove = [key for key in blocklistthingy[item][BLOCKDATATYPE][itemm].keys() if key not in keys_to_keep]
                            for key in keys_to_remove:
                             blocklistthingy[item][""][itemm].pop(key, None)
                             truepower1 = False
                            try:
                             DICTX = {}
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Type"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["vmtransactionnum"]
                             DICTX["YES"] = blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]
                            except:
                             truepower1 = False
                            blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]= remove_sql(blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"])

            
                            verifyingkey = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]]["Verifyingkey"]
                            verifyingkey2 = EASYTOUSEDATATHING[blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]]["Verifyingkey"]
                            price = blocklistthingy[item][BLOCKDATATYPE][itemm]["amountofcoins"]
                            transactionfee = blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]
                            txextra = blocklistthingy[item][BLOCKDATATYPE][itemm]["txextra"]
                            verifyingsig = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig1"]
                            try:
                                           verifyingsig = base64.b64decode(verifyingsig)
                            except Exception as e:
                                      print("Error: "+str(e))
                            verifyingsig2 = blocklistthingy[item][BLOCKDATATYPE][itemm]["verifyingsig2"]
                            try:
                                           verifyingsig2 = base64.b64decode(verifyingsig2)
                            except Exception as e:
                                      print("Error: "+str(e))
                            sender = blocklistthingy[item][BLOCKDATATYPE][itemm]["Sender"]
                            reciever = blocklistthingy[item][BLOCKDATATYPE][itemm]["Reciever"]
                            vmtransactionnum = blocklistthingy[item][BLOCKDATATYPE][itemm]["vmtransactionnum"]
           
                            verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
                            try:
                             verifyingkey.verify(
                              verifyingsig2,
                              verifythis2.encode('utf-8'),
                              ec.ECDSA(hashes.SHA256())
                             )
                            except:
                             print("LMESSUP!@1")
                             truepower1 = False
                            verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)

                            try:
                             verifyingkey2.verify(
                              verifyingsig,
                              verifythis.encode('utf-8'),
                              ec.ECDSA(hashes.SHA256())
                             )
                            except:
                             print("LMESSUP!@2")
                             truepower1 = False
                            if truepower1==True and WALLETVALUES[sender]["Coins"]>=(price+transactionfee) and not txextra in WALLETVALUES[sender]["txextras"] and not txextra in WALLETVALUES[reciever]["txextras"] and price%1==0 and transactionfee%1==0:
                             WALLETVALUES[sender]["Coins"]+=-1*(price+transactionfee)
                             WALLETVALUES[reciever]["Coins"]+=price
                             WALLETVALUES[sender]["txextras"][txextra]= "yes"
                             WALLETVALUES[reciever]["txextras"][txextra]= "yes"
                             transactionfeetotal+=blocklistthingy[item][BLOCKDATATYPE][itemm]["transactionfee"]

                            else:
                             if truepower1 == False:
                              print("TYPE4VERIFICATIONERROR")
                             if WALLETVALUES[sender]["Coins"]<=(price+transactionfee):
                              print("TYPE4PRICEERROR")
                             if txextra in WALLETVALUES[sender]["txextras"]:
                              print("TYPE4TXEXTRAERROR")
                             if txextra in WALLETVALUES[reciever]["txextras"]:
                              print("TYPE4TXEXTRAERROR2")
                             if price%1<0 or price%1>0:
                              print("TYPE4PRICE%ERROR")
                             if transactionfee%1>0 or transactionfee%1<0:
                              print("TYPE4TRANSACTIONFEE%ERROR")
                             truethingthing2 = False
                             PROOFOFHAPPEN3 = False
                             blockreward = 420000*(10**8)
                             blocksuntildoom = 5
                             itemswentthrough = 0
                             del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                             break 
                       print("WALLETS:"+str(WALLETVALUES))
                       print("FIRSTSENDER: "+str(blocklistthingy[item]["FirstSender"]))
                       WALLETVALUES[blocklistthingy[item]["FirstSender"]]["Coins"]+= blockreward
                       WALLETVALUES[blocklistthingy[item]["FirstSender"]]["Coins"]+=transactionfeetotal
                       print("Step 6")
                       print("PROOFOFHAPPEN3: "+str(PROOFOFHAPPEN3))
                       itemswentthrough+=1
                       blocksuntildoom+=-1
                       if blocksuntildoom == 0:
                          if itemswentthrough<7:
                               blocksuntildoom=210000
                               blockreward = 45*(10**8)
                          else:
                               blocksuntildoom = 210000
                               blockreward = math.floor(blockreward/2)
                       blocknumthing = len(blocklistthingy.keys())
                       COMBINETHEMFOREVERLOL = {}
                       for item in EASYTOUSEDATATHING:
                           verifyingkey = EASYTOUSEDATATHING[item]["Verifyingkey"]
                           print("verifyingkey: "+str(verifyingkey))
                           coins = WALLETVALUES[item]["Coins"]
                           COMBINETHEMBOTHFOREVERLOL[item] = {"verifyingkey":verifyingkey,"Coins":coins,"txextras":WALLETVALUES[item]["txextras"],"Verifyingkeysummoningthing":EASYTOUSEDATATHING[item]["Verifyingkeysummoningthing"]}
                       Walletnumthing = len(EASYTOUSEDATATHING)
                       FINISHEDTHESTUFF4EVER = False
                       PROOFOFHAPPEN33 = True
                       datalistpower = {}
                       datalistpower2 = {}
                   print("Step 7")
                   print("PROOFOFHAPPEN3: "+str(PROOFOFHAPPEN3))
                   if PROOFOFHAPPEN3 == True:
                            print("Step 8")
                            if FINISHEDTHESTUFF4EVER == True:
                             TOTALPOWERVALUE=False
                            serverthingthing.setblockchain(blocklistthingy)
                            serverthingthing.setwalletlist(COMBINETHEMBOTHFOREVERLOL)
                            serverthingthing.setdoomblocks(doomblocks)
                            serverthingthing.setblockreward(blockreward)
                            while FINISHEDTHESTUFF4EVER == False:
                             NEWBLOCKNUM3 = 0
                             blocklenthing = 0
                             try:
                              NEWBLOCKNUM = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getblocknum")
                              NEWBLOCKNUM = NEWBLOCKNUM.json()
                              print("NEWBLOCKNUMDATA: "+str(NEWBLOCKNUM))
                              NEWBLOCKNUM = NEWBLOCKNUM["Success"]
                              blocklenthing = len(blocklistthingy.keys())+1
                              print("BLOCKLENTHING: "+str(blocklenthing))
                              NEWBLOCKNUM3 = int(NEWBLOCKNUM)
                              servers = {}
                             except:
                               lol=True
                             print("Step 9")

                             print("NEWBLOCKNUM3: "+str(NEWBLOCKNUM3))
                             print("blocklenthing: "+str(blocklenthing))
                             if blocklenthing >= int(NEWBLOCKNUM3):
                              print("Step 10")
                              savedservers = dict(trueserverlist["Data"])
                              print("SavedServers: "+str(savedservers))
                              deletionnumber = 0
                              rangenum = 0
                              minimumnumber = 0
                              for item in savedservers:
                                  if savedservers[item] == urltosendto:
                                     print("URLTOSENDTO: "+str(urltosendto))
                                     deletionnumber = rangenum
                                  else:
                                     rangenum+=1
                              del savedservers[str(deletionnumber)]
                              if deletionnumber == 0:
                                  minimumnumber = 1
                              print("Minimumnumber")
                              try:
                                  print("URL TO SEND TO: "+str(urltosendto))
                                  servers=requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/recieveservers2")
                                  servers = servers.json()
                                  servers = servers["Success"]
                              except Exception as e:
                                  
                                  print("WE LOST!!! Error: "+str(e))
                                  try:
                                   for i in range(5):
                                  
                                    number = random.randint(minimumnumber,len(savedservers))
                                    rangenum = 1
                                    truenumber = 0
                                    for item in savedservers:
                                        if rangenum == number:
                                            print("SavedServers: "+str(savedservers))
                                            truenumber = str(item)
                                            print("Truenumber: "+str(truenumber))
                                    if len(savedservers) == 1 and '0' in savedservers:
                                        number = 0
                                    try:
                                     servers=requests.get(str(trueserverlist["NEWDATA"][savedservers[str(truenumber)]]["PROTOCOL"])+str(savedservers[str(truenumber)])+"/recieveservers2")
                                     servers = servers.json()
                                     servers = servers["Success"]
                                     urltosendto = str(savedservers[str(truenumber)])
                                     break
                                    except:
                                     del savedservers[number]
                                     print("Well that failed")
                                  except Exception as e:
                                   print("Well that failed.....: "+str(e))
                              if SpecialDevice == 1:
                                data = {"type":1,"IP":SpecialDomain,"Verifyingkey":public_pem.decode('utf-8'),"fileprice":PriceperGBperday,"ramgbprice":RAMPRICEPERGB,"datatransferprice":DATATRANSFERPRICEPERGB,"vcpuprice":VCPUPRICE,"PortThing":0,"PROTOCOL":httpthingy,"MINERCHECK":"YES","NODECHECK":"YES"}
                              else:
                                data = {"type":1,"IP":str(get_local_ip()),"Verifyingkey":public_pem.decode('utf-8'),"fileprice":PriceperGBperday,"ramgbprice":RAMPRICEPERGB,"datatransferprice":DATATRANSFERPRICEPERGB,"vcpuprice":VCPUPRICE,"PortThing":SPECIALPORT,"PROTOCOL":httpthingy,"MINERCHECK":"YES","NODECHECK":"YES"}
                              serverthingthing.setverifyingkeyamount(Walletnumthing)
                              serverthingthing.setblocknum(NEWBLOCKNUM3)
                              with open("TheData.txt","w") as file:
                                  file.write(str(data))
                              try:
                               try:
                                requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/addnewserver",json=data)
                               except:
                                print("WELL WE'RE HERE THOUGH!")
                                deletethisone = ""
                                for item in trueserverlist["Data"]:
                                    if trueserverlist["Data"][item] == urltosendto:
                                        deletethisone = str(item)
                                del trueserverlist["Data"][item]
                                randomnum = random.randint(1,len(trueserverlist["Data"]))
                                rangenumthingy2 = 1
                                for item in trueserverlist["Data"]:
                                   if randomnum == rangenumthingy2:
                                       print("WE'RE HERE")
                                       urltosendto = trueserverlist["Data"][str(item)]
                                       print("URLTOSENDTO: "+str(urltosendto))
                                   else:
                                    print("RANDOMNUM: "+str(randomnum))
                                    print("Rangenumthing: "+str(rangenumthingy2))
                                    print("UGH!!!!!!!!!")
                                    rangenumthingy2+=1
                               print("Well it's not this......")
                               walletamountnum = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeynum")
                               walletamountnum = walletamountnum.json()
                               print("WALLETNUMAMOUNT: "+str(walletamountnum))
                               data2 = {"beginnum":Walletnumthing}
                               
                               servers = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/recieveservers")
                               print("SERVERS:"+str(servers))
                               servers = servers.json()
                               print("SERVERS2:"+str(servers))

                               servers = servers["Success"]
                               verifyingkeydatalist = {}
                               verifyingkeyhashdatalist  ={}
                               keydatanumber = 1
                               for item in servers:
                                if keydatanumber>5:
                                    break
                                urltosendto2 = servers[item]
                                try:
                                 verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto2]["PROTOCOL"]+urltosendto2+"/getsomeoftheverifyingkeys",json=data2)
                                 if verifyingkeys22.status_code == 200:
                                  verifyingkeys22 = verifyingkeys22.json()
                                  print("VERIFYINGKEYS: "+str(verifyingkeys22))
                                  verifyingkeys22 = verifyingkeys22["Success"]
                                  hashthis = ""
                                  for item in verifyingkeys22:
                                    hashthis = hashthis+str(verifyingkeys22[item]["walletname"])
                                    hashthis = hashthis+str(verifyingkeys22[item]["verifyingkey"])
                                  hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                  if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                  else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                  verifyingkeydatalist[hashthis] = verifyingkeys22
                                  keydatanumber+=1
                                except:
                                    print("WE COULDNT DO THIS!")
                               highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
                               verifyingkeys22 = verifyingkeydatalist[str(highest_item)]
                               for item in verifyingkeys22:
                                   walletname = verifyingkeys22[item]["walletname"]
                                   verifyingkeything = verifyingkeys22[item]["verifyingkey"]
                                   verifyingkeything = convertthething(verifyingkeything).encode('utf-8')
                                   serverthingthing.createwallet(walletname,verifyingkeything)
                               FINISHEDTHESTUFF4EVER = True
                               TOTALPOWERVALUE = False
                               FIRSTWAVE = False
                               try:
                                changethat600thingthing = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getthecurrent600thing")
                                serverthingthing.loadfilesintoself()
                                serverthingthing.loadfilespaceintoself()
                                serverthingthing.loadvmstufflistintoself()
                                serverthingthing.loadvmdatalistintoself()
                                serverthingthing.loadvmdatalist2intoself()
                                serverthingthing.loadlistofkeyeysintoself()
                                print("Step 11")

                                if changethat600thingthing.status_code == 200:
                                   print("Step 12")

                                   changethat600thingthing = changethat600thingthing.json()
                                   changethat600thingthing = changethat600thingthing["Success"]
                                   print("600thing:"+str(changethat600thingthing))
                                   with open("timeatstart.txt","w") as file:
                                       file.write(str(time.time()))
                                   if changethat600thingthing>0:
                                       the600thing = changethat600thingthing
                                       changethat600thing = True
                                       with open("changethe600thing.txt","w") as file:
                                                file.write(str(changethat600thingthing))
                                       themega600thing = 0
                                       with open("changethe600thing.txt","r") as file:
                                         themega600thing = float(file.read())
                                         print("THEMEGA600THING: "+str(themega600thing))
                                         serverthingthing.setthe600thing(themega600thing)
                                       the600thing = themega600thing
                                       if  themega600thing>=-3 and themega600thing<=0:


                                        with open("countdownthing.txt","w") as file:
                                           if themega600thing>=-1:
                                            file.write(str(themega600thing))

                                           else:
                                            if themega600thing>-3:
                                             file.write(str(themega600thing))
                                        
                                        print("THE COUNTDOWNTHING: "+str(themega600thing+3))
                                        countdownthing = int(themega600thing)
                                       else:
                                                with open("changethe600thing.txt","w") as file:
                                                 file.write(themega600thing)
                                               
                                                the600thing =themega600thing
                                                serverthingthing.setthe600thing(the600thing)
                                                countdownthing = 0

                                                if themega600thing<-3:
                                                 
                                                 
                                                 with open("changethe600thing.txt","w") as file:
                                                  file.write(str(themega600thing))
                                                 with open("countdownthing.txt","w") as file:
                                                  file.write(str(0))
                                                 the600thing = themega600thing
                                       print("wHAT?")
                                   else:
                                       try:
                                        changethecountdownthing = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getthealtthing")
                                        if changethecountdownthing.status_code == 200:
                                           changethecountdownthing =changethecountdownthing.json()
                                           changethecountdownthing = changethecountdownthing["Success"]
                                           print("OVER HERE!!!!")
                                           changethecountdownthing = float(changethecountdownthing)
                                           if changethecountdownthing>0:
                                               changethat600thing = True
                                               changethecountdownthing = float(changethecountdownthing)-5
                                               runthecountdowthing = True
                                               the600thing = float(changethecountdownthing)
                                               with open("changethe600thing.txt","w") as file:
                                                file.write(str((float(changethecountdownthing))))
                                               countdownthing = changethecountdownthing
                                           else:
                                              the600thing = 600
                                              changethat600thing = True
                                              timethingthing = True
                                             
                                              with open("changethe600thing.txt","w") as file:
                                               file.write(str((changethat600thingthing)))
                                              with open("countdownthing.txt","w") as file:
                                                  file.write(changethecountdownthing)
                                       except Exception as e:
                                           print("ERROR: "+str(e))
                                           lol=True
                                   print("Step 13")
                                   dictofletters = []
                                   stringthing = ""
                                   for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
                                    dictofletters.append(letter)
                                   for i in range(18):
                                    numthing = random.randint(0,len(dictofletters)-1)
                                    stringthing = stringthing+dictofletters[numthing]
       
                                   seed_phrase = stringthing
                                   with open("seedphrase.txt","w") as file:
                                    file.write(seed_phrase)
# Convert the BIP39 seed phrase to a seed
                                   stringthingx = ""
                                   for i in range(18):
                                    numthing = random.randint(0,len(dictofletters)-1)
                                    stringthingx = stringthingx+str(dictofletters[numthing])
                                   with open("walletname.txt","w") as file:
                                    file.write(stringthingx)

# Derive a cryptographic key from the seed phrase using PBKDF2
                                   salt = "22".encode('utf-8')  # Generate a random salt
                                   kdf = PBKDF2HMAC(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=salt,
                                    iterations=100000,
                                    backend=default_backend()
                                   )
                                   key = kdf.derive(seed_phrase.encode())

# Generate a private key using the derived key as the seed for deterministic RNG
                                   private_key39 = ec.derive_private_key(
                                    int.from_bytes(key, byteorder='big'),  # Using derived key as seed
                                    ec.SECP256R1(),  # Choosing an elliptic curve (you can choose a different one if needed)
                                    backend=default_backend()
                                   )

# Serialize the private key        
                                   private_pem = private_key39.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                   )
                                   print("Step 14")
                                   with open("privatepemtxt.txt","w") as file:
                                    file.write(private_pem.decode('utf-8'))
       
# Serialize the public key
                                   public_key38 = private_key39.public_key()
                                   public_pemLOL = public_key38.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                   )
                                   with open("publicpemtxt.txt","w") as file:
                                    file.write(public_pemLOL.decode('utf-8'))
                                   serverthingthing.createwallet(stringthingx,public_pemLOL)
                                   verifyingkeything444 = serverthingthing.getverificationkey(stringthingx)
                                   verifyingkeything444 =convertthething(verifyingkeything444)
                                   print(load_pem_public_key(verifyingkeything444.encode('utf-8'), default_backend()))
                                   serverthingthing.changewallet(stringthingx)
                                   wallet = serverthingthing.getselfwallet()
                                   if wallet == stringthingx:
                                    print("YES")
                                   else:
                                    print("WTF")
                                   print("Step 15")
                                   ramgb = get_ram_info()
                                   serverthingthing.setRAM(ramgb)
                                   if serverthingthing.checkforwallet(stringthingx) == "YES":
                                    print("Yeah")
                                   else:
                                    print("WTF")
       

                                   num_vcpus = psutil.cpu_count(logical=True)
                                   print("VCPUS: "+str(num_vcpus))
                                   serverthingthing.setVCPUS(num_vcpus)

                                   print("TEDDY FARE")
                                   selfwallet = serverthingthing.getselfwallet()
                                   print(selfwallet)
                                   data = {"walletname":stringthingx,"publickey":public_pemLOL.decode('utf-8')}
                                   dataxx = {"walletname":stringthingx}
                                   response = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+str(urltosendto)+"/createwallet",json=data)
                                   walletbalance = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+str(urltosendto)+"/getwalletbalance",json=dataxx)
                                   print("Walletbalance: "+str(walletbalance))
                                   serverthingthing.setverifyingkey(private_key39)
                                   print(serverthingthing.getverificationkey(stringthingx))
                                   print("WALLETVALUES7500:  "+str(WALLETVALUES))
                               except:
                                    lol=True
                              except Exception as e:
                                   print("CODENAME!: "+str(e))
                             else:
                              try:
                               data = {"Blockamount":int(blocklenthing)}
                               print("step 10")
                               blocks = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getblocknum")
                               blocks = blocks.json()
                               if blocklenthing == int(NEWBLOCKNUM3):
                                 print("HOW IS THIS HAPPENING? THIS DOESNT MAKE SENSE! STOP THIS MADNESS NOW!")
                                 CHECKEDCORRECTLY = True
                             
                               blocks = blocks["Success"]
                               blocklenthing = int(blocks)
                               print("BLOCKLENTHING: "+str(blocklenthing))
                             
                               try:
                                print("step 11")
                                
                                datalistpower = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getsomeoftheblocks",json=data)
                                datalistpower = datalistpower.json()
                                datalistpower = datalistpower["Success"]
                                datalistpower = dict(datalistpower)
                                blocknumthing = len(datalistpower)
                                data2 = {"beginnum":Walletnumthing}
                                print("BLOCKLENTHING: "+str(blocklenthing))
                                try:
                                 print("step 12")
                                 verifyingkeydatalist = {}
                                 verifyingkeyhashdatalist  ={}
                                 keydatanumber = 1
                                 for item in servers:
                                  if keydatanumber>5:
                                    break
                                  urltosendto = trueserverlist[item]
                                  verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getsomeoftheverifyingkeys",json=data2)
                                  verifyingkeys22 = verifyingkeys22.json()
                                  print("VERIFYINGKEYS: "+str(verifyingkeys22))
                                  verifyingkeys22 = verifyingkeys22["Success"]
                                  hashthis = ""
                                  for item in verifyingkeys22:
                                    hashthis = hashthis+str(verifyingkeys22[item]["walletname"])
                                    hashthis = hashthis+str(verifyingkeys22[item]["verifyingkey"])
                                  hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                  if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                  else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                  verifyingkeydatalist[hashthis] = verifyingkeys22
                                  keydatanumber+=1
                                 highest_item = max(verifyingkeydatalist(), key=lambda x: verifyingkeyhashdatalist[x]['Count'])
                                 datalistpower2 = verifyingkeydatalist[str(highest_item)]
                                 print("DATALISTPOWER2: "+str(datalistpower2))
                                 maxblocknum = time.time()-timestartdate
                                 maxblocknum = maxblocknum/603
                                 COMBINETHEMBOTHFOREVERLOL2={}
                                 if maxblocknum<blocklenthing:
                                   datalistpower2 = {}
                               
                                 for item in datalistpower2:
                                   wallet = datalistpower2[item]["walletname"]
                                   verifyingkey = datalistpower2[item]["verifyingkey"]
                                   EASYTOUSEDATATHING[wallet] = {"Verifyingkey":verifyingkey}
                                   WALLETVALUES[wallet] = {"Coins":0,"txextras":[]}
                                 for item in datalistpower:
                                  transactionfeetotal = 0
                                 if PROOFOFHAPPEN33 == False:
                                    break
                                 for itemm in datalistpower[item]["BlockData"]:
                                  if datalistpower[item]["BlockData"][itemm]["Type"] == 1 :
                                   print("Yes")
                                   keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig","transactionfee","lol"}  # Define keys that should be kept
                           
                                   keys_to_remove = [key for key in datalistpower[item]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                                   for key in keys_to_remove:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   try:
                                     DICTX = {}
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["Type"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["amountofcoins"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["Sender"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["Reciever"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["txextra"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["verifyingsig"]
                                     DICTX["YES"]=datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                   except:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   datalistpower[item]["Blockdata"][itemm]["txextra"]=remove_sql( datalistpower[item]["Blockdata"][itemm]["txextra"])

                           
                                   if datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[ datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"]:
                                    print("FOUND IT")
                                   if WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"] >= (datalistpower[item]["Blockdata"][itemm]["amountofcoins"] +  datalistpower[item]["Blockdata"][itemm]["transactionfee"]) and not  datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[ datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"] and  datalistpower[item]["Blockdata"][itemm]["amountofcoins"]%1==0 and  datalistpower[item]["Blockdata"][itemm]["transactionfee"]%1==0 and len( datalistpower[item]["Blockdata"][itemm]["txextra"])==10 and  datalistpower[item]["Blockdata"][itemm]["amountofcoins"]>0:
                                    print("YEA")
                                    print( datalistpower[item]["Blockdata"][itemm]["txextra"])
                                    publickeything = EASYTOUSEDATATHING[ datalistpower[item]["Blockdata"][itemm]["Sender"]]["Verifyingkey"]
                                    print(publickeything)
                                    print(datalistpower[item]["Blockdata"][itemm]["verifyingsig"])
                                    signature =   datalistpower[item]["Blockdata"][itemm]["verifyingsig"]
                                    try:
                                           signature = base64.b64decode(signature)
                                    except Exception as e:
                                      print("Error: "+str(e))
                                    messagething = str( datalistpower[item]["Blockdata"][itemm]["Sender"]) + str( datalistpower[item]["Blockdata"][itemm]["Reciever"]) + str( datalistpower[item]["Blockdata"][itemm]["amountofcoins"]) + str( datalistpower[item]["Blockdata"][itemm]["transactionfee"]) + str( datalistpower[item]["Blockdata"][itemm]["txextra"])
                                    print(signature)
                                    message = messagething.encode('utf-8')
                                    print(messagething)
                                    try:
                                     publickeything.verify(
                                     signature,
                                     message,
                                     ec.ECDSA(hashes.SHA256())
                                    )
                           
                                    except Exception as e:
                                     PROOFOFHAPPEN33 = False
                                     blockreward = 420000*(10**8)
                                     blocksuntildoom = 5
                                     itemswentthrough = 0
                                     blocknumthing = 0
                                     Walletnumthing = 0 
                                     WALLETVALUES = {}
                                     EASYTOUSEDATATHING = {}
                                     COMBINETHEMBOTHFOREVERLOL2 ={}
                                     blocklistthingy = {}
                                     datalistpower = {}
                                     del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                     break 
                                    try:
                                     int(datalistpower[item]["Blockdata"][itemm]["amountofcoins"])
                                     int(datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                    except:
                                     PROOFOFHAPPEN33 = False
                                     blockreward = 420000*(10**8)
                                     blocksuntildoom = 5
                                     itemswentthrough = 0
                                     blocknumthing = 0
                                     Walletnumthing = 0 
                                     WALLETVALUES = {}
                                     EASYTOUSEDATATHING = {}
                                     COMBINETHEMBOTHFOREVERLOL2 ={}
                                     blocklistthingy = {}
                                     datalistpower = {}
                                     del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                     break 
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"] += -(datalistpower[item]["Blockdata"][itemm]["amountofcoins"] +  datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"][datalistpower[item]["Blockdata"][itemm]["txextra"]] = {"yes"}
                                    transactionfeetotal+=datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                   else:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                  elif datalistpower[item]["Blockdata"][itemm]["Type"] == 2:
                                   keys_to_remove = [key for key in datalistpower[item]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                                   for key in keys_to_remove:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   try:
                                    DICTX = {}
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Type"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["fileprice"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["Sender"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["Reciever"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["txextra"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["txextra2"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["filesize"]
                                    DICTX["YES"] =datalistpower[item]["Blockdata"][itemm]["filehash"]
                                   except:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   datalistpower[item]["Blockdata"][itemm]["txextra"]= remove_sql(blocklistthingy[item]["Blockdata"][itemm]["txextra"])
                                   datalistpower[item]["Blockdata"][itemm]["txextra2"]= remove_sql(blocklistthingy[item]["Blockdata"][itemm]["txextra2"])

                                   print("Started Up")
                                   try:
                                    int( datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                    int( datalistpower[item]["Blockdata"][itemm]["fileprice"])
                                   except:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break  
                           
                         
         
                                  verifythis = str(datalistpower[item]["Blockdata"][itemm]["filesize"])+str(datalistpower[item]["Blockdata"][itemm]["daysoflasting"])+str(datalistpower[item]["Blockdata"][itemm]["Reciever"])+str(datalistpower[item]["Blockdata"][itemm]["fileprice"])+str(datalistpower[item]["Blockdata"][itemm]["txextra"])+str(datalistpower[item]["Blockdata"][itemm]["filehash"])+str(datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                  print("VERIFYTHISPART2: "+str(verifythis))
                                  verifythis2 = str(datalistpower[item]["Blockdata"][itemm]["txextra2"])+str(datalistpower[item]["Blockdata"][itemm]["fileprice"])+str(datalistpower[item]["Blockdata"][itemm]["transactionfee"])+".0"         
                                  print("Part2: "+str(verifythis2))
                                  signature = datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                  try:
                                           signature = base64.b64decode(signature)
                                  except Exception as e:
                                      print("Error: "+str(e))
                                  signature2 = datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                  try:
                                           signature2 = base64.b64decode(signature2)
                                  except Exception as e:
                                      print("Error: "+str(e))
                                  publickeything = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Verifyingkey"]
                                  publickeything2 = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["Verifyingkey"]
                                  TRUEPOWERTHING = False
                                  TRUEPOWERTHING2 = False
                                  if not datalistpower[item]["Blockdata"][itemm]["fileprice"]+datalistpower[item]["Blockdata"][itemm]["transactionfee"]< WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"] or datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"] or datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["txextras"] or not len(datalistpower[item]["Blockdata"][itemm]["txextra2"]) == 10 or not datalistpower[item]["Blockdata"][itemm]["transactionfee"]%1==0 or not datalistpower[item]["Blockdata"][itemm]["fileprice"]%1 == 0 and datalistpower[item]["Blockdata"][itemm]["fileprice"]>0 and datalistpower[item]["Blockdata"][itemm]["transactionfee"]>0:
                                   TRUEPOWERTHING = False
                                   TRUEPOWERTHING2 = False
            
                           
           
                                   print("Reasons for failure:")
    
                                   if  (datalistpower[item]["Blockdata"][itemm]["fileprice"] + datalistpower[item]["Blockdata"][itemm]["transactionfee"]) > WALLETVALUES[blocklistthingy[item]["Blockdata"][itemm]["Sender"]]["Coins"]:
                                    print("Insufficient coins in Sender's wallet")

                                   if datalistpower[item]["Blockdata"][itemm]["txextra"] in \
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"]:
                                    print("txextra already exists in Sender's txextras")

                                   if datalistpower[item]["Blockdata"][itemm]["txextra"] in \
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["txextras"]:
                                    print("txextra already exists in Receiver's txextras")

                                   if not len(datalistpower[item]["Blockdata"][itemm]["txextra"]) == 10:
                                    print("Invalid length of txextra")

                                   if not datalistpower[item]["Blockdata"][itemm]["transactionfee"] % 1 == 0:
                                    print("Transaction fee is not a whole number")

                                   if not datalistpower[item]["Blockdata"][itemm]["fileprice"] % 1 == 0 or \
                                     datalistpower[item]["Blockdata"][itemm]["fileprice"] <= 0 or \
                                     datalistpower[item]["Blockdata"][itemm]["transactionfee"] <= 0:
                                     print("Invalid file price or transaction fee")

                           
                                   try:
                                    publickeything.verify(
                                     signature,
                                     verifythis2.encode('utf-8'),
                                     ec.ECDSA(hashes.SHA256())
                                    )
                                    TRUEPOWERTHING = True
                                   except:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   try:
                                    publickeything2.verify(
                                     signature2,
                                     verifythis.encode('utf-8'),
                                     ec.ECDSA(hashes.SHA256())
                                    )
                                    TRUEPOWERTHING2 = True
         
                                   except:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                   if TRUEPOWERTHING == True and TRUEPOWERTHING2 == True:
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"]+=-(datalistpower[item]["Blockdata"][itemm]["fileprice"]+datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"][datalistpower[item]["Blockdata"][itemm]["txextra"]] = "yes"
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["txextras"][datalistpower[item]["Blockdata"][itemm]["txextra"]] = "yes"
                                    WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["Coins"]+=datalistpower[item]["Blockdata"][itemm]["fileprice"]
                                    transactionfeetotal+=datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                    print("IT IS DONE.")
                                   else:
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                  elif datalistpower[item]["Blockdata"][itemm]["Type"] == 3:
                                     print("COME")
                         

                                     try:
                                      int(datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                      int(datalistpower[item]["Blockdata"][itemm]["filepricething"])
                                     except:
                                      PROOFOFHAPPEN33 = False
                                      blockreward = 420000*(10**8)
                                      blocksuntildoom = 5
                                      itemswentthrough = 0
                                      blocknumthing = 0
                                      Walletnumthing = 0 
                                      WALLETVALUES = {}
                                      EASYTOUSEDATATHING = {}
                                      COMBINETHEMBOTHFOREVERLOL2 ={}
                                      blocklistthingy = {}
                                      datalistpower = {}
                                      del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                      break 
                                     keys_to_keep = {'Type', 'filepricething',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","daysoflasting","filespace","pendingtransactionnum","lol"}  # Define keys that should be kept
        
                                     truethough = True
                                     keys_to_remove = [key for key in datalistpower[item]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                                     for key in keys_to_remove:
                                      truethingthing2 = False
                                      PROOFOFHAPPEN3 = False
                                      blockreward = 420000*(10**8)
                                      blocksuntildoom = 5
                                      itemswentthrough = 0
                                      del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                      break 
                                     try:
                                      DICTX = {}
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Type"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["filepricething"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Sender"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Reciever"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["txextra"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                      DICTX["YES"] =  datalistpower[item]["Blockdata"][itemm]["filespace"]
                                      DICTX["YES"] =  datalistpower[item]["Blockdata"][itemm]["daysoflasting"]
                                      DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["pendingtransactionnum"]
                                     except:
                                       PROOFOFHAPPEN33 = False
                                       blockreward = 420000*(10**8)
                                       blocksuntildoom = 5
                                       itemswentthrough = 0
                                       blocknumthing = 0
                                       Walletnumthing = 0 
                                       WALLETVALUES = {}
                                       EASYTOUSEDATATHING = {}
                                       COMBINETHEMBOTHFOREVERLOL2 ={}
                                       blocklistthingy = {}
                                       datalistpower = {}
                                       del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                       break 
                                     datalistpower[item]["Blockdata"][itemm]["txextra"]= remove_sql(datalistpower[item]["Blockdata"][itemm]["txextra"])
                          
                                     verifyingkey1 = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Verifyingkey"]
                                     verifyingkey2 = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["Verifyingkey"]
                                     verifyingsig1 = datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                     try:
                                           verifyingsig1 = base64.b64decode(verifyingsig1)
                                     except Exception as e:
                                      print("Error: "+str(e))
                                     verifyingsig2 = datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                     try:
                                           verifyingsig2 = base64.b64decode(verifyingsig2)
                                     except Exception as e:
                                      print("Error: "+str(e))
                                     verifythis1 = str(datalistpower[item]["Blockdata"][itemm]["pendingtransactionnum"])+str(datalistpower[item]["Blockdata"][itemm]["filespace"])+str(datalistpower[item]["Blockdata"][itemm]["daysoflasting"])+str(datalistpower[item]["Blockdata"][itemm]["Reciever"])+str(datalistpower[item]["Blockdata"][itemm]["txextra"])+str(datalistpower[item]["Blockdata"][itemm]["filepricething"])+str(datalistpower[item]["Blockdata"][itemm]["transactionfee"])

                                     try:
                                      verifyingkey1.verify(
                                       verifyingsig1,
                                       verifythis1.encode('utf-8'),
                                       ec.ECDSA(hashes.SHA256())
                                      )
                                     except:
                                      truethough = False
                                      print("MESSUPREASON: 2")
                                     verifythis2 = str(datalistpower[item]["Blockdata"][itemm]["pendingtransactionnum"])+str(datalistpower[item]["Blockdata"][itemm]["filespace"])+str(datalistpower[item]["Blockdata"][itemm]["daysoflasting"])+str(datalistpower[item]["Blockdata"][itemm]["Sender"])+str(datalistpower[item]["Blockdata"][itemm]["filepricething"])+str(datalistpower[item]["Blockdata"][itemm]["Reciever"])+datalistpower[item]["Blockdata"][itemm]["txextra"]+str(datalistpower[item]["Blockdata"][itemm]["transactionfee"])

                                     try:
                                      verifyingkey2.verify(
                                       verifyingsig2,
                                       verifythis2.encode('utf-8'),
                                       ec.ECDSA(hashes.SHA256())
                                      )
                                     except:
                                      print("MESSUPREASON: 3")
                                      truethough = False
                                     if truethough == True and WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"]>=(datalistpower[item]["Blockdata"][itemm]["filepricething"]+datalistpower[item]["Blockdata"][itemm]["transactionfee"]) and not datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"] and not datalistpower[item]["Blockdata"][itemm]["txextra"] in WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["txextras"] and datalistpower[item]["Blockdata"][itemm]["transactionfee"]%1==0 and datalistpower[item]["Blockdata"][itemm]["filepricething"]%1==0 and datalistpower[item]["Blockdata"][itemm]["filepricething"]>0 and datalistpower[item]["Blockdata"][itemm]["transactionfee"]>0:
                                      WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Coins"]+=-(datalistpower[item]["Blockdata"][itemm]["filepricething"]+blocklistthingy[item]["Blockdata"][itemm]["transactionfee"])
                                      WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Sender"]]["txextras"][datalistpower[item]["Blockdata"][itemm]["txextra"]]= "yes"
                                      WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["txextras"][datalistpower[item]["Blockdata"][itemm]["txextra"]]= "yes"
                                      WALLETVALUES[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["Coins"]+=datalistpower[item]["Blockdata"][itemm]["filepricething"]
                                      transactionfeetotal+=datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                     else:
                                       PROOFOFHAPPEN33 = False
                                       blockreward = 420000*(10**8)
                                       blocksuntildoom = 5
                                       itemswentthrough = 0
                                       blocknumthing = 0
                                       Walletnumthing = 0 
                                       WALLETVALUES = {}
                                       EASYTOUSEDATATHING = {}
                                       COMBINETHEMBOTHFOREVERLOL2 ={}
                                       blocklistthingy = {}
                                       datalistpower = {}
                                       del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                       break 
                                  elif datalistpower[item]["Blockdata"][itemm]["Type"] == 4:
                                   print("Come")

                                   keys_to_keep = {'Type', 'amountofcoins',"Sender","Reciever","txextra","verifyingsig1","transactionfee","verifyingsig2","vmtransactionnum","lol"}  # Define keys that should be kept
                                   truepower1 = True
                                   try:
                                    int(datalistpower[item]["Blockdata"][itemm]["amountofcoins"])
                                    int(datalistpower[item]["Blockdata"][itemm]["transactionfee"])
                                   except:
                                       PROOFOFHAPPEN33 = False
                                       blockreward = 420000*(10**8)
                                       blocksuntildoom = 5
                                       itemswentthrough = 0
                                       blocknumthing = 0
                                       Walletnumthing = 0 
                                       WALLETVALUES = {}
                                       EASYTOUSEDATATHING = {}
                                       COMBINETHEMBOTHFOREVERLOL2 ={}
                                       blocklistthingy = {}
                                       datalistpower = {}
                                       del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                       break 
                                   keys_to_remove = [key for key in datalistpower[item]["Blockdata"][itemm].keys() if key not in keys_to_keep]
                                   for key in keys_to_remove:
                                    datalistpower[item]["Blockdata"][item].pop(key, None)
                                    truepower1 = False
                                   try:
                                    DICTX = {}
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Type"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["amountofcoins"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Sender"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["Reciever"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["vmtransactionnum"]
                                    DICTX["YES"] = datalistpower[item]["Blockdata"][itemm]["txextra"]
                                   except:
                                    truepower1 = False
                                   datalistpower[item]["Blockdata"][itemm]["txextra"]= remove_sql(datalistpower[item]["Blockdata"][itemm]["txextra"])

            
                                   verifyingkey = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Reciever"]]["Verifyingkey"]
                                   verifyingkey2 = EASYTOUSEDATATHING[datalistpower[item]["Blockdata"][itemm]["Sender"]]["Verifyingkey"]
                                   price = datalistpower[item]["Blockdata"][itemm]["amountofcoins"]
                                   transactionfee = datalistpower[item]["Blockdata"][itemm]["transactionfee"]
                                   txextra = datalistpower[item]["Blockdata"][itemm]["txextra"]
                                   verifyingsig = datalistpower[item]["Blockdata"][itemm]["verifyingsig1"]
                                   try:
                                           verifyingsig = base64.b64decode(verifyingsig)
                                   except Exception as e:
                                      print("Error: "+str(e))
                                   verifyingsig2 = datalistpower[item]["Blockdata"][itemm]["verifyingsig2"]
                                   try:
                                           verifyingsig2 = base64.b64decode(verifyingsig2)
                                   except Exception as e:
                                      print("Error: "+str(e))
                                   sender = datalistpower[item]["Blockdata"][itemm]["Sender"]
                                   reciever = datalistpower[item]["Blockdata"][itemm]["Reciever"]
                                   vmtransactionnum = datalistpower[item]["Blockdata"][itemm]["vmtransactionnum"]
           
                                   verifythis2 = "Price:"+str(price)+"walletname:"+str(sender)+"txextra:"+str(txextra)+"pendingvmnum:"+str(vmtransactionnum)+"selfwallet:"+str(reciever)+"transactionfee:"+str(transactionfee)
                                   try:
                                    verifyingkey.verify(
                                     verifyingsig2,
                                     verifythis2.encode('utf-8'),
                                     ec.ECDSA(hashes.SHA256())
                                    )
                                   except:
                                    print("LMESSUP!@1")
                                    truepower1 = False
                                   verifythis = str(price)+sender+txextra+str(vmtransactionnum)+reciever+str(transactionfee)

                                   try:
                                    verifyingkey2.verify(
                                     verifyingsig,
                                     verifythis.encode('utf-8'),
                                     ec.ECDSA(hashes.SHA256())
                                    )
                                   except:
                                    print("LMESSUP!@2")
                                    truepower1 = False
                                   if truepower1==True and WALLETVALUES[sender]["Coins"]>=(price+transactionfee) and not txextra in WALLETVALUES[sender]["txextras"] and not txextra in WALLETVALUES[reciever]["txextras"] and price%1==0 and transactionfee%1==0:
                                    WALLETVALUES[sender]["Coins"]+=-1*(price+transactionfee)
                                    WALLETVALUES[reciever]["Coins"]+=price
                                    WALLETVALUES[sender]["txextras"][txextra]= "yes"
                                    WALLETVALUES[reciever]["txextras"][txextra]= "yes"
                                    transactionfeetotal+=datalistpower[item]["Blockdata"][itemm]["transactionfee"]

                                   else:
                                    if truepower1 == False:
                                     print("TYPE4VERIFICATIONERROR")
                                    if WALLETVALUES[sender]["Coins"]<=(price+transactionfee):
                                     print("TYPE4PRICEERROR")
                                    if txextra in WALLETVALUES[sender]["txextras"]:
                                     print("TYPE4TXEXTRAERROR")
                                    if txextra in WALLETVALUES[reciever]["txextras"]:
                                     print("TYPE4TXEXTRAERROR2")
                                    if price%1<0 or price%1>0:
                                     print("TYPE4PRICE%ERROR")
                                    if transactionfee%1>0 or transactionfee%1<0:
                                     print("TYPE4TRANSACTIONFEE%ERROR")
                                    PROOFOFHAPPEN33 = False
                                    blockreward = 420000*(10**8)
                                    blocksuntildoom = 5
                                    itemswentthrough = 0
                                    blocknumthing = 0
                                    Walletnumthing = 0 
                                    WALLETVALUES = {}
                                    EASYTOUSEDATATHING = {}
                                    COMBINETHEMBOTHFOREVERLOL2 ={}
                                    blocklistthingy = {}
                                    datalistpower = {}
                                    del HashList[hashthingthingthing]["Serverswithhash"][randomserver]
                                    break 
                                except Exception as e:
                                    print("THE ERROR: "+str(e))
                                    lol=True
                                WALLETVALUES[datalistpower[item]["FirstSender"]]["Coins"]+= blockreward
                                WALLETVALUES[datalistpower[item]["FirstSender"]]["Coins"]+=transactionfeetotal
                                print("WORKING!!!!!!!!")
                                itemswentthrough+=1
                                blocksuntildoom-=1
                                if blocksuntildoom == 0:
                                 if itemswentthrough<7:
                                  blockreward = 45*(10**8)
                                  blocksuntildoom=210000
                                 else:
                                  blockreward = math.floor(blockreward/2)
                                  blocksuntildoom=210000
                               except Exception as e:
                                   print("THE ERROR: "+str(e))

                                   lol=True
                              except Exception as e:
                                  print("ERROR@#: "+str(e))
                                  lol=True
                              try:
                               NEWBLOCKNUM2 = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getblocknum")
                               NEWBLOCKNUM2 = NEWBLOCKNUM2.json()
                               NEWBLOCKNUM2 = NEWBLOCKNUM2["Success"]
                               if blocklenthing == int(NEWBLOCKNUM2):
                                       print("WE DID IT!")
                               else:
                                       PROOFOFHAPPEN33 = False
                              except:
                                  print("Failed!")
                              print("PROOFOFHAPPEN33: "+str(PROOFOFHAPPEN33))
                              if PROOFOFHAPPEN33 == True:
                                   print("WERE HERE!")
                                   try:
                                     servers=requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/recieveservers2")
                                     servers = servers.json()
                                     servers = servers["Success"]
                                   except:
                                    print("WE LOST!!!")
                                   for item in servers:
                                    serverthingthing.listserver(servers[item]["server"],servers[item]["altserver"],servers[item]["Fileprice"],load_pem_public_key(convertthething(servers[item]["verifyingkey"]).encode('utf-8'),backend=default_backend),servers[item]["RAMGBPRICE"],servers[item]["VCPUPRICE"],servers[item]["DATATRANSFERGB"],servers[item]["portthing"],servers[item]["MINERCHECK"],servers[item]["NODECHECK"],servers[item]["verifyingkey"],servers[item]["PROTOCOL"])
                                    try:
                                     serverthingthing.addtimeaddedtimetoserver(servers[item]["server"],servers[item]["timeadded"])
                                    except:
                                        print("WE've FAILED!")
                                   blocklenthing = int(NEWBLOCKNUM3)
                                   ITEMPOWERNUM = 0
                                   POWERVAL = False
                                   print("Datalistpower: "+str(datalistpower))
                                   serverthingthing.setblockchain(blocklistthingy)
                                   serverthingthing.setblockchain(datalistpower)
                                   COMBINETHEMBOTHFOREVERLOL2={}
                                   serverthingthing.setblockreward(blockreward)
                                   serverthingthing.setdoomblocks(doomblocks)
                                   for item in datalistpower2:
                                       Wallet = datalistpower2[item]["walletname"]
                                       Verifyingkey = datalistpower2[item]["verifyingkey"]
                                       Coins = WALLETVALUES[Wallet]["Coins"]
                                       COMBINETHEMBOTHFOREVERLOL2[Wallet] = {"verifyingkey":load_pem_public_key(convertthething(str(Verifyingkey)).encode('utf-8'),backend=default_backend)
,"Coins":Coins,"txextras":WALLETVALUES[Wallet]["txextras"],"Verifyingkeysummoningthing":Verifyingkey}
                                  
                                   serverthingthing.setwalletlist(COMBINETHEMBOTHFOREVERLOL2)
                                   FINISHEDTHESTUFF4EVER = True
                                   if SpecialDevice == 1:
                                    data = {"type":1,"IP":SpecialDomain,"Verifyingkey":public_pem.decode('utf-8'),"Fileprice":PriceperGBperday,"ramgbprice":RAMPRICEPERGB,"datatransferprice":DATATRANSFERPRICEPERGB,"vcpuprice":VCPUPRICE,"PortThing":0,"PROTOCOL":httpthingy,"MINERCHECK":"YES","NODECHECK":"YES"}
                                   else:
                                    data = {"type":1,"IP":str(get_local_ip()),"Verifyingkey":public_pem.decode('utf-8'),"Fileprice":PriceperGBperday,"ramgbprice":RAMPRICEPERGB,"datatransferprice":DATATRANSFERPRICEPERGB,"vcpuprice":VCPUPRICE,"PortThing":SPECIALPORT,"PROTOCOL":httpthingy,"MINERCHECK":"YES","NODECHECK":"YES"}
                                   serverthingthing.setverifyingkeyamount(Walletnumthing)
                                   serverthingthing.setblocknum(NEWBLOCKNUM3)
                                   try:
                                     requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/addnewserver",json=data)
                                   except:
                                    lol=True
                                   walletamountnum = 0
                                   try:
                                    walletamountnum = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeynum")
                                    walletamountnum = walletamountnum.json()
                                    walletamountnum = int(walletamountnum["Success"])
                                   except:
                                    lol=True
                                   data2 = {"beginnum":Walletnumthing,"endnum":walletamountnum}
                                   try:
                                    servers = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getservers")
                                    verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getsomeoftheverifyingkeys",json=data2)
                                   except:
                                    lol=True
                                   verifyingkeys22 = verifyingkeys22.json()
                                   verifyingkeys22 = verifyingkeys22["Success"]
                                   for item in verifyingkeys22:
                                     walletname = verifyingkeys22[item]["walletname"]
                                     verifyingkeything = verifyingkeys22[item]["verifyingkey"]
                                     serverthingthing.createwallet(walletname,verifyingkeything)
                                   FINISHEDTHESTUFF4EVER = True
                                   FIRSTWAVE = False
                                   TOTALPOWERVALUE=False
                                   print("YES!")

                                   try:
                                    changethat600thingthing = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getthecurrent600thing")
                                   except:
                                    lol=True
                                  
                                   serverthingthing.loadfilesintoself()
                                   serverthingthing.loadfilespaceintoself()
                                   serverthingthing.loadvmstufflistintoself()
                                   serverthingthing.loadvmdatalistintoself()
                                   serverthingthing.loadvmdatalist2intoself()
                                   serverthingthing.loadlistofkeyeysintoself()
                                   serverthingthing.setdoomblocks(blocksuntildoom)
                                   serverthingthing.setblockreward(blockreward)
                                   selfip = get_local_ip()
                                   print(selfip)
                                   serverthingthing.listserver(selfip,"NONE",PriceperGB,public_key3333333,RAMPRICEPERGB,VCPUPRICE,DATATRANSFERPRICEPERGB,SPECIALPORT,"YES","YES",str(public_pem),httpthingy)
                                   changethat600thing = True
                                   timethingthing = True
                                   dictofletters = []
                                   stringthing = ""
                                   for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
                                    dictofletters.append(letter)
                                   for i in range(18):
                                    numthing = random.randint(0,len(dictofletters)-1)
                                    stringthing = stringthing+dictofletters[numthing]
       
                                   seed_phrase = stringthing
                                   with open("seedphrase.txt","w") as file:
                                    file.write(seed_phrase)
# Convert the BIP39 seed phrase to a seed
                                   stringthingx = ""
                                   for i in range(18):
                                    numthing = random.randint(0,len(dictofletters)-1)
                                    stringthingx = stringthingx+str(dictofletters[numthing])
                                   with open("walletname.txt","w") as file:
                                    file.write(stringthingx)

# Derive a cryptographic key from the seed phrase using PBKDF2
                                   salt = "22".encode('utf-8')  # Generate a random salt
                                   kdf = PBKDF2HMAC(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=salt,
                                    iterations=100000,
                                    backend=default_backend()
                                   )
                                   key = kdf.derive(seed_phrase.encode())

# Generate a private key using the derived key as the seed for deterministic RNG
                                   private_key39 = ec.derive_private_key(
                                    int.from_bytes(key, byteorder='big'),  # Using derived key as seed
                                    ec.SECP256R1(),  # Choosing an elliptic curve (you can choose a different one if needed)
                                    backend=default_backend()
                                   )

# Serialize the private key
                                   private_pem = private_key39.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                   )
                                   with open("privatepemtxt.txt","w") as file:
                                    file.write(private_pem.decode('utf-8'))
       
# Serialize the public key
                                   public_key38 = private_key39.public_key()
                                   public_pemLOL = public_key38.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                   )
                                   with open("publicpemtxt.txt","w") as file:
                                    file.write(public_pemLOL.decode('utf-8'))
                                   serverthingthing.createwallet(stringthingx,public_pemLOL)
                                   verifyingkeything444 = serverthingthing.getverificationkey(stringthingx)
                                   verifyingkeything444 =convertthething(verifyingkeything444)
                                   print(load_pem_public_key(verifyingkeything444.encode('utf-8'), default_backend()))
                                   serverthingthing.changewallet(stringthingx)
                                   wallet = serverthingthing.getselfwallet()
                                   if wallet == stringthingx:
                                    print("YES")
                                   else:
                                    print("WTF")
                                   ramgb = get_ram_info()
                                   serverthingthing.setRAM(ramgb)
                                   if serverthingthing.checkforwallet(stringthingx) == "YES":
                                    print("Yeah")
                                   else:
                                    print("WTF")
       

                                   num_vcpus = psutil.cpu_count(logical=True)
                                   print("VCPUS: "+str(num_vcpus))
                                   serverthingthing.setVCPUS(num_vcpus)
                                   data = {"walletname":stringthingx,"publickey":public_pemLOL.decode('utf-8')}

                                   requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+str(urltosendto)+"/createwallet",json=data)

                                   print("TEDDY FARE")
                                   selfwallet = serverthingthing.getselfwallet()
                                   print(selfwallet)
                                   serverthingthing.setverifyingkey(private_key39)
                                   print(serverthingthing.getverificationkey(stringthingx))
                                   print("WALLETVALUES7500:  "+str(WALLETVALUES))
                                   try:
                                    changethat600thingthing = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getthecurrent600thing")
                                    if changethat600thingthing.status_code == 200:
                                     changethat600thingthing = changethat600thingthing.json()
                                     changethat600thingthing = changethat600thingthing["Success"]
                                     print("FINAL600THING: "+str(changethat600thingthing))
                                     if float(changethat600thingthing)>0:
                                       changethat600thing = True
                                       with open("changethe600thing.txt","w") as file:
                                                file.write(str(changethat600thingthing-5))
                                                the600thing = changethat600thingthing-5
                                                serverthingthing.setthe600thing(the600thing)
                                     else:
                                       try:
                                        changethecountdownthing = requests.get(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getthealtthing")
                                      
                                       except:
                                           lol=True
                                       if changethecountdownthing.status_code == 200:
                                           print("Changethecountdownthing: "+str(changethecountdownthing))
                                           changethecountdownthing = changethecountdownthing.json()
                                           changethecountdownthing=changethecountdownthing["Success"]
                                           if float(changethecountdownthing)>0:
                                               
                                               changethat600thing = True
                                               
                                               runthecountdowthing = True
                                               the600thing = float(changethecountdownthing)
                                               with open("changethe600thing.txt","w") as file:
                                                file.write(str(changethat600thingthing-5))
                                           else:
                                              the600thing = 600
                                              changethat600thing = True
                                              timethingthing = True
                                             
                                              with open("changethe600thing.txt","w") as file:
                                               file.write(str(the600thing-5))

                                   except Exception as e:
                                    print("WHAT WENT WRONG HERE?: "+str(e))
                                    lol=True
                                  
        
elif allowedtostartpowerserver == True:
    print("Don't shut it down. This takes 10 minutes to start, remember?")
    blocknum =serverthingthing.getblockamount()
    
    if blocknum == 1:
       selfip = get_local_ip()
       print(selfip)
       serverthingthing.listserver(selfip,"NONE",PriceperGB,public_key3333333,RAMPRICEPERGB,VCPUPRICE,DATATRANSFERPRICEPERGB,SPECIALPORT,"YES","YES",str(public_pem),"http://")
       changethat600thing = True
       timethingthing = True
       dictofletters = []
       stringthing = ""
       for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
           dictofletters.append(letter)
       for i in range(18):
           numthing = random.randint(0,len(dictofletters)-1)
           stringthing = stringthing+dictofletters[numthing]
       
       seed_phrase = stringthing
       with open("seedphrase.txt","w") as file:
           file.write(seed_phrase)
# Convert the BIP39 seed phrase to a seed
       stringthingx = ""
       for i in range(18):
           numthing = random.randint(0,len(dictofletters)-1)
           stringthingx = stringthingx+str(dictofletters[numthing])
       with open("walletname.txt","w") as file:
           file.write(stringthingx)

# Derive a cryptographic key from the seed phrase using PBKDF2
       salt = "22".encode('utf-8')  # Generate a random salt
       kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
       )
       key = kdf.derive(seed_phrase.encode())

# Generate a private key using the derived key as the seed for deterministic RNG
       private_key39 = ec.derive_private_key(
        int.from_bytes(key, byteorder='big'),  # Using derived key as seed
        ec.SECP256R1(),  # Choosing an elliptic curve (you can choose a different one if needed)
        backend=default_backend()
       )

# Serialize the private key
       private_pem = private_key39.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
       )
       with open("privatepemtxt.txt","w") as file:
           file.write(private_pem.decode('utf-8'))
       
# Serialize the public key
       public_key38 = private_key39.public_key()
       public_pemLOL = public_key38.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
       )
       with open("publicpemtxt.txt","w") as file:
           file.write(public_pemLOL.decode('utf-8'))
       serverthingthing.createwallet(stringthingx,public_pemLOL)
       verifyingkeything444 = serverthingthing.getverificationkey(stringthingx)
       verifyingkeything444 =convertthething(verifyingkeything444)
       print(load_pem_public_key(verifyingkeything444.encode('utf-8'), default_backend()))
       serverthingthing.changewallet(stringthingx)
       wallet = serverthingthing.getselfwallet()
       if wallet == stringthingx:
           print("YES")
       else:
           print("WTF")
       ramgb = get_ram_info()
       serverthingthing.setRAM(ramgb)
       if serverthingthing.checkforwallet(stringthingx) == "YES":
           print("Yeah")
       else:
           print("WTF")
       

       num_vcpus = psutil.cpu_count(logical=True)
       print("VCPUS: "+str(num_vcpus))
       serverthingthing.setVCPUS(num_vcpus)
       serverthingthing.gothroughthetransactionlist()
       
       
       print("Teddy Fair")
       serverthingthing.acceptablockpuppy()
       print("TEDDY FARE")
       selfwallet = serverthingthing.getselfwallet()
       print(selfwallet)
       serverthingthing.setverifyingkey(private_key39)
       print(serverthingthing.getverificationkey(stringthingx))
selfwallet = serverthingthing.getselfwallet()
print("SelfWallet: "+str(selfwallet))
if selfwallet == "":
                                       print("Step 13")
                                       dictofletters = []
                                       stringthing = ""
                                       for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
                                        dictofletters.append(letter)
                                       seed_phrase = createseedphrase()
                                       with open("seedphrase.txt","w") as file:
                                        file.write(seed_phrase)
# Convert the BIP39 seed phrase to a seed
                                       stringthingx = ""
                                       for i in range(18):
                                        numthing = random.randint(0,len(dictofletters)-1)
                                        stringthingx = stringthingx+str(dictofletters[numthing])
                                       with open("walletname.txt","w") as file:
                                        file.write(stringthingx)

# Derive a cryptographic key from the seed phrase using PBKDF2
                                       salt = "22".encode('utf-8')  # Generate a random salt
                                       kdf = PBKDF2HMAC(
                                        algorithm=hashes.SHA256(),
                                        length=32,
                                        salt=salt,
                                        iterations=100000,
                                        backend=default_backend()
                                       )
                                       key = kdf.derive(seed_phrase.encode())

# Generate a private key using the derived key as the seed for deterministic RNG
                                       private_key39 = ec.derive_private_key(
                                        int.from_bytes(key, byteorder='big'),  # Using derived key as seed
                                        ec.SECP256R1(),  # Choosing an elliptic curve (you can choose a different one if needed)
                                        backend=default_backend()
                                       )

# Serialize the private key        
                                       private_pem = private_key39.private_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption()
                                       )
                                       print("Step 14")
                                       with open("privatepemtxt.txt","w") as file:
                                        file.write(private_pem.decode('utf-8'))
       
# Serialize the public key
                                       public_key38 = private_key39.public_key()
                                       public_pemLOL = public_key38.public_bytes(
                                         encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo
                                       )
                                       with open("publicpemtxt.txt","w") as file:
                                        file.write(public_pemLOL.decode('utf-8'))
                                       serverthingthing.createwallet(stringthingx,public_pemLOL)
                                       verifyingkeything444 = serverthingthing.getverificationkey(stringthingx)
                                       verifyingkeything444 =convertthething(verifyingkeything444)
                                       print(load_pem_public_key(verifyingkeything444.encode('utf-8'), default_backend()))
                                       serverthingthing.changewallet(stringthingx)
                                       wallet = serverthingthing.getselfwallet()
                                       if wallet == stringthingx:
                                        print("YES")
                                       else:
                                        print("WTF")
                                       print("Step 15")
                                       ramgb = get_ram_info()
                                       serverthingthing.setRAM(ramgb)
                                       if serverthingthing.checkforwallet(stringthingx) == "YES":
                                        print("Yeah")
                                       else:
                                        print("WTF")
       

                                       num_vcpus = psutil.cpu_count(logical=True)
                                       print("VCPUS: "+str(num_vcpus))
                                       serverthingthing.setVCPUS(num_vcpus)

                                       print("TEDDY FARE")
                                       selfwallet = serverthingthing.getselfwallet()
                                       print(selfwallet)
                                       data = {"walletname":stringthingx,"publickey":public_pemLOL.decode('utf-8')}

                                       requests.post("http://"+str(urltosendto)+"/createwallet",json=data)
                                       serverthingthing.setverifyingkey(private_key39)
                                       print(serverthingthing.getverificationkey(stringthingx))
                                       print("WALLETVALUES7500:  "+str(WALLETVALUES))
                                              
with open("changethe600thing.txt","w") as file:
    file.write(str(the600thing))
with open("countdownthing.txt","w") as file:
    file.write(str(countdownthing))
print("TEDDY BEAR")
mysteriousdevice = "98358385838583583"
def loop1():
 print("Is it doing anything?")
 def t600thingactivate():
     the600thing = serverthingthing.the600get()
     if the600thing<-1:
        serverthingthing.the600reset()
     serverthingthing.the600fix()
     return str(the600thing)
 def countdownthingactivate():
     countdownthing = serverthingthing.thecountdownget()
     serverthingthing.thecountdownfix()


     if countdownthing <0.25:

               serverthingthing.acceptablockpuppy()
               serverthingthing.thecountdownreset()


               serverthingthing.the600reset()

     return str(countdownthing)
 the600thing = 600
 timeatstarttime = 0
 with open("changethe600thing.txt","w") as file:
     file.write(str(600))
 totaltime = 3
 with open("changethe600thing.txt","r") as file:
    fileread = str(file.read())
    if float(fileread)>0:
     themega600thing = float(fileread)-totaltime

     if themega600thing<0 and themega600thing>=-3:
         countdownthing = ConvertTheNumber(themega600thing)-3
         if countdownthing<0:
             the600thing = 600+countdownthing
             with open("changethe600thing.txt","w") as file:
                 file.write(str(the600thing))
         with open("countdownthing.txt","w") as file:
             file.write(str(countdownthing))
     elif themega600thing<0:

         the600thing = ConvertTheNumber(themega600thing)-3
         with open("changethe600thing.txt","w") as file:
             file.write(str(the600thing))
     else:
         if the600thing%3 == 0 and not the600thing%2 == 0:
             countdownthing = ConvertTheNumber(themega600thing)
             with open("countdownthing.txt","w") as file:
                 file.write(str(countdownthing))
         else:
          the600thing = ConvertTheNumber(themega600thing)


          with open("changethe600thing.txt","w") as file:
             file.write(str(the600thing))

    else:
        with open("countdownthing.txt","r") as file:
            themegacountdownthing = float(file.read())-totaltime
            themegacountdownthing = ConvertTheNumber(themegacountdownthing)-2
            #if it is 2 off switch 2 to four

            the600thing = themegacountdownthing
            with open("changethe600thing.txt","w") as file:
                file.write(str(the600thing))
 averagetimelist = 0
 averagetimecount = 0
 while True:
     print("We're not in here????")
     while the600thing>0:
         starttime = time.time()
         time.sleep(0.25)

         try:
          print("YOU BETTER TRY")
          response23 = ""
          if SpecialDevice == 2:
           response23 = t600thingactivate()
       
           the600thing = float(response23)
           print("the600thing: "+str(the600thing))
           countdownthing = 3
          else:
           response23 =t600thingactivate()
        
  
           print("the600thing: "+str(the600thing))

           the600thing = float(response23)
           countdownthing = 3

         except Exception as e:
             print("ERROR!: "+str(e))
             lol=True
         endtime = time.time()
         truetime = endtime-starttime
         averagetimelist+=truetime
         averagetimecount+=1
         trueaveragetime = averagetimelist/averagetimecount
     serverthingthing.gothroughthetransactionlist()

     loadloop = True
     numthing=3
     while numthing>0:
      time.sleep(0.25)
      try:
       response222 = ""
       response222 = countdownthingactivate()

       responsedata = response222
       numthing = float(responsedata)
       print("Numthing: "+str(numthing))
       if numthing<0.3:
          loadloop = False

          serverthingthing.the600reset()
          the600thing = serverthingthing.the600get()
       else:
         lol=True

      except Exception as e:
         lol=True

         

load_pem_public_key(convertthething(str(public_pem)).encode('utf-8'),backend=default_backend)
print("LOL@@@")
def loop3(timethingthing,timewaitthing):
 while timethingthing == True:
     time.sleep(0.01)
     if not timewaitthing == 0:
         timewaitthing+=-0.01
     else:
        serverthingthing.getridoftransactions()
        timewaitthing = 1800
print("LOL@@@#")
def loop4(thepowerthing):
 
 while thepowerthing == "False":
    time.sleep(10)
    tablething = get_disk_info2()
    for item in tablething:
        try:
         serverthingthing.addharddrive(item)
        except:
            print("LOL")
        serverthingthing.changeharddrivedata(str(item),int(str(tablething[item]["availabledata"])))
print("###")
def loop5(LOOPTHEFILEPRICECHECK):

 while LOOPTHEFILEPRICECHECK == "True":
  
     time.sleep(10)
     if not PriceperGBbutFIAT == "NONE":
      sendNEWPRICE()
     serverlist = serverthingthing.getservers()
     serverlen = len(serverlist)
     servernum = random.randint(0,serverlen-1)
     server = "http://"+str(serverlist[servernum])+"/getfilepricechange"
     selfserver = get_local_ip()
     signature = private_key3333.sign(
       str(PriceperGB).encode('utf-8'),
       ec.ECDSA(hashes.SHA256())
     )
     encoded_signature = base64.b64encode(signature).decode('utf-8')

     data = {"newfileprice":PriceperGB,"server":selfserver+str(":")+str(SPECIALPORT),"verifyingsig":encoded_signature}
     respone = requests.post(server,json=data)
     print("WE HAVE WON!")
def loop19(LOOPTHEFILEPRICECHECK):

 while LOOPTHEFILEPRICECHECK == "True":
     time.sleep(10)
     if not VCPUPRICEFIAT == -1:
      sendNEWPRICE()
     serverlist = serverthingthing.getservers()
     serverlen = len(serverlist)
     servernum = random.randint(0,serverlen-1)
     server = "http://"+str(serverlist[servernum])+"/getvcpupricechange"
     selfserver = get_local_ip()
     signature = private_key3333.sign(
       str(PriceperGB).encode('utf-8'),
       ec.ECDSA(hashes.SHA256())
     )
     encoded_signature = base64.b64encode(signature).decode('utf-8')

     data = {"newfileprice":VCPUPRICE,"server":selfserver+str(":")+str(SPECIALPORT),"verifyingsig":encoded_signature}
     respone = requests.post(server,json=data)
     print("WE HAVE WON!")
      
def loop20(LOOPTHEFILEPRICECHECK):

  while LOOPTHEFILEPRICECHECK == "True":
     time.sleep(10)
     if not DATATRANSFERPRICEPERGBFIAT == -1:
      sendNEWPRICE()
     serverlist = serverthingthing.getservers()
     serverlen = len(serverlist)
     servernum = random.randint(0,serverlen-1)
     server = "http://"+str(serverlist[servernum])+"/getdatatransferpricechange"
     selfserver = get_local_ip()
     signature = private_key3333.sign(
       str(PriceperGB).encode('utf-8'),
       ec.ECDSA(hashes.SHA256())
     )
     encoded_signature = base64.b64encode(signature).decode('utf-8')

     data = {"newfileprice":DATATRANSFERPRICEPERGB,"server":selfserver+str(":")+str(SPECIALPORT),"verifyingsig":encoded_signature}
     respone = requests.post(server,json=data)
     print("WE HAVE WON!")
  
def loop21(LOOPTHEFILEPRICECHECK):

  while LOOPTHEFILEPRICECHECK == "True":
   try:
     time.sleep(10)
     if not RAMPRICEPERGBFIAT == -1:
      sendNEWPRICE()
     serverlist = serverthingthing.getservers()
     serverlen = len(serverlist)
     servernum = random.randint(0,serverlen-1)
     server = "http://"+str(serverlist[servernum])+"/getramgbpricechange"
     selfserver = get_local_ip()
     signature = private_key3333.sign(
       str(PriceperGB).encode('utf-8'),
       ec.ECDSA(hashes.SHA256())
     )
     encoded_signature = base64.b64encode(signature).decode('utf-8')

     data = {"newfileprice":RAMPRICEPERGB,"server":selfserver+str(":")+str(SPECIALPORT),"verifyingsig":encoded_signature}
     respone = requests.post(server,json=data)
     print("WE HAVE WON!")
   except:
       lol = True
print("##()")
def loop6():
    while True:
        time.sleep(1800)
        serverthingthing.listfilelistasafile()
        serverthingthing.listfilespacelistasafile()
print("######")
def loop7(PriceperGBbutFIAT):
    
    while True:
     time.sleep(10)
     if  PriceperGBbutFIAT == "NONE":
         print("LOL")
     else:
       try:
        with open("pricepergbbutfiat.txt","r") as file:
            newpricepergb = file.read()
            PriceperGBbutFIAT = float(newpricepergb)
       except:
           with open("pricepergbbutfiat.txt","w") as file:
               file.write(str(PriceperGBbutFIAT))
           print("A major issue identified")
print(3)
def loop8(RAMPRICEPERGBFIAT):
    
    while True:
     time.sleep(10)
     if RAMPRICEPERGBFIAT == "-1":
         print("LOL")
     else:
       try:
        with open("rampergbbutfiat.txt","r") as file:
            newRAMPRICEPERGB = file.read()
            RAMPRICEPERGBFIAT = float(newRAMPRICEPERGB)
       except:
           with open("rampergbbutfiat.txt","w") as file:
               file.write(str(RAMPRICEPERGBFIAT))
print(5)
def loop9(DATATRANSFERPRICEPERGBFIAT):
    
    while True:
     time.sleep(10)
     if  DATATRANSFERPRICEPERGBFIAT == "-1":
         print("LOL")
     else:
       try:
        with open("DATATRANSFERpricepergbbutfiat.txt","r") as file:
            newDATATRANSFERPRICEPERGB = file.read()
            DATATRANSFERPRICEPERGBFIAT= float(newDATATRANSFERPRICEPERGB)
       except:
           lol=True
           lol=True
           with open("DATATRANSFERpricepergbbutfiat.txt","w") as file:
               file.write(str(DATATRANSFERPRICEPERGB))
print(54)
def loop10(PriceperGBbutFIAT):
    while True:
     time.sleep(10)
     if PriceperGBbutFIAT == "-1":
         print("LOL")
     else:
       try:
        with open("VCPUPRICEFIAT.txt","r") as file:
            newVCPUPRICEPERGB = file.read()
            VCPUPRICEFIAT= float(newVCPUPRICEPERGB)
       except:
           lol=True
           with open("VCPUPRICEFIAT.txt","w") as file:
               file.write(str(VCPUPRICEFIAT))
print(542)
def loop11():
    while True:
      try:
        time.sleep(100)
        sendNEWPRICE()
        sendNEWDATATRANSFERPRICE()
        sendNEWRAMPRICE()
        sendNEWVCPUPRICE()
      except:
          lol=True
print(534)
def loop12():
    while True:
        time.sleep(10)
        serverthingthing.removethesillytransactions()
print(514)
def loop13():
    while True:
        time.sleep(1500)
        serverthingthing.vmstufflistlistasafile()
print(254)
def loop14():
    while True:
        time.sleep(3)
        serverthingthing.GOTHROUGHVMS()
print(354)
def loop15():
    while True:
        time.sleep(3000)
        for item in VMDATALIST2:
            serverthingthing.checkVMTHINGYTIMEY(str(item))
print(541)
def loop16():
    while True:
        time.sleep(1500)
        serverthingthing.LISTVMDATALISTASFILE()
print(5341)
def loop17():
    while True:
        time.sleep(1500)
        serverthingthing.LISTVMDATALIST2ASFILE()
print(5241)
def loop18():
    while True:
        time.sleep(1500)
        serverthingthing.LISTKEYEYESASFILE()
print(2456)
thread1 = threading.Thread(target=loop1)
print("1")
print("2")
thread3 = threading.Thread(target=loop3,args=(timethingthing,timewaitthing))
print("3")
thread4 = threading.Thread(target=loop4,args=(str(thepowerthing),))
print(4)
thread5 = threading.Thread(target=loop5,args=(str(LOOPTHEFILEPRICECHECK),))
thread19 = threading.Thread(target=loop19,args=(str(LOOPTHEFILEPRICECHECK),))
thread20 = threading.Thread(target=loop20,args=(str(LOOPTHEFILEPRICECHECK),))
thread21 = threading.Thread(target=loop21,args=(str(LOOPTHEFILEPRICECHECK),))

print(5)
thread6 = threading.Thread(target=loop6)
print(6)
thread7 = threading.Thread(target=loop7,args=(str(PriceperGBbutFIAT),))
thread8 = threading.Thread(target=loop8,args=(str(RAMPRICEPERGBFIAT),))
thread9 = threading.Thread(target=loop9,args=(str(DATATRANSFERPRICEPERGBFIAT),))
thread10 = threading.Thread(target=loop10,args=(str(VCPUPRICEFIAT),))
thread11 = threading.Thread(target=loop11)
thread12 = threading.Thread(target=loop12)
thread13 = threading.Thread(target=loop13)
thread14 = threading.Thread(target=loop14)
thread15 = threading.Thread(target=loop15)
thread16=threading.Thread(target=loop16)
thread17=threading.Thread(target=loop17)
thread18=threading.Thread(target=loop18)
# Start the threads
thread1.start()
thread3.start()
thread4.start()
thread5.start()
thread6.start()
thread7.start()
thread8.start()
thread9.start()
thread10.start()
thread11.start()
thread12.start()
thread13.start()
thread14.start()
thread15.start()
thread16.start()
thread17.start()
thread18.start()
thread19.start()
thread20.start()
thread21.start()
max_drive = serverthingthing.setmaxdrive()
servers = serverthingthing.getservers()
print("Servers: "+str(servers))
print("Wallet: "+str(serverthingthing.getselfwallet()))
# Wait for the threads to finish (You can use Ctrl+C to stop execution)
if SpecialDevice == 2:
    SpecialDomain = str(get_local_ip())
serverthingthing.listserver(SpecialDomain,"101.101.101.101",PriceperGB,private_key3333,RAMPRICEPERGB,VCPUPRICE,DATATRANSFERPRICEPERGB,SPECIALPORT,"YES","YES",str(public_pem),httpthingy)
print("LOCALIP2: "+str(get_local_ip2()))
if __name__ == "__main__":
    local_ip = get_local_ip2()
    port = 1000
    app.run(host="0.0.0.0", port=SPECIALPORT)

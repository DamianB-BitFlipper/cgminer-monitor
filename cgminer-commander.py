#Copyright (c) 2014, John Smith slimcoin@anche.no

#
# cgminer-commander
# John Smith | Contact: slimcoin@anche.no
# https://github.com/JSmith-BitFlipper/cgminer-monitor
# BTC 1AsxJdSafUdES2HvAZt2pnF7DiPeunBRKn
# LTC LVD6egk3rF8se2xNgwGgvJfyvSBU8VV3nX
# PPC PTKehuReGEASb6EyUYj1V7JEMz5M6DdBBU
# DOGE DJwTG3P4jG8ujKvwfhBV6Bps39nriU5Ty4
#


#
# Usage:
#    ****Make sure the user settings below are correct****
#    Run the command with --help or -h
#


#Email stuff
import smtplib
import imaplib
import email
from email import parser

import sys
import time

#crypto stuff
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random

########USER SETTINGS########

#change if not using gmail
# the best way to find the sever addresses is to do a web search
# append the SSL or TSL port at the end
#script may crash if there is a port on imap, leave it without a port
email_smtp_server = 'smtp.gmail.com:587'
email_imap_server = 'imap.gmail.com'

__login__ = 'login_username'
__pass__ = 'login_password'
email_from = 'example@email.com'
email_to = 'example@email.com'

###########IMPORTANT###########
#Be sure that the monitor script has the same values for the these variables

#all emails from the monitor script will start with this
email_uniq_monitor_signature = 'Miner'

#all emails from this script will start with this
email_uniq_commander_signature = 'Commander'
###########IMPORTANT###########

#Subjects must be the same in cgminer-monitor script
email_command_subject = "Do"  #subject of commanding emails
email_command_subject_help = 'Help'  #subject of emails requesting help on the command email usage

email_encrypt = True  #should outgoing mail be encrypted
email_decrypt = True  #should incomming mail commands be decrypted

#Be sure the encryption password matches the miner's decryption password and vice-vera
email_encrypt_key = b'Super Secure Passphrase Goes Here'  #encryption passphrase
email_decrypt_key = b'Super Secure Passphrase Goes Here'  #decryption passphrase 

########USER SETTINGS########

##################################Crypto stuff##################################
email_encrypt_key_hash = hashlib.sha256(email_encrypt_key).digest()
email_decrypt_key_hash = hashlib.sha256(email_encrypt_key).digest()

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = len(email_encrypt_key_hash)

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
##################################Crypto stuff##################################

#
# Crypto-stuff
#

def encrypt(plain_text, passphrase = email_encrypt_key_hash):
    cipher = AES.new(passphrase)
    message = EncodeAES(cipher, plain_text)
    return message

def decrypt(encrypted_text, passphrase = email_decrypt_key_hash):
    cipher = AES.new(email_encrypt_key_hash)
    dec = DecodeAES(cipher, encrypted_text)
    return dec

def CheckRecievingSignature(message):
    words = message['Subject'].split('_')

    if words == []:
        return False

    #first word in subject must be the uniq_signature from the miner
    if words[0] != email_uniq_monitor_signature:
        return False

    return True

def SendEmail(from_addr, to_addr_list, cc_addr_list,
              subject, message, login, password,
              smtpserver = email_smtp_server):
    header = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Cc: %s\n' % ','.join(cc_addr_list)
    header += 'Subject: %s\n\n' % (email_uniq_commander_signature + '_' + subject)

    #encrypt the message
    if email_encrypt == True:
        message = encrypt(message)

    server = smtplib.SMTP(smtpserver)
    server.starttls()
    server.login(login, password)
    server.sendmail(from_addr, to_addr_list, header + message)
    server.quit()


def GetNewMinerEmail(login, password, imapserver = email_imap_server):
    server = imaplib.IMAP4_SSL(imapserver)

    try:
        server.login(login, password)
    except:
        print "Error: Unable to login to Email"
        sys.exit(1)

    server.select(readonly = False)
    (retcode, messages) = server.search(None, '(UNSEEN)')

    # no new emails
    if messages[0] == '':
        return []

    if retcode == 'OK':
        all_msg = []
        for num in messages[0].split(' '):
            #get the email's information
            typ, data = server.fetch(num, '(RFC822)')
            msg = email.message_from_string(data[0][1])
            #mark the email as seen 
            typ, data = server.store(num, '+FLAGS', '(\\Seen)')

            try:
                if CheckRecievingSignature(msg) == True:
                    #if the email should be decrypted
                    if email_decrypt == True:
                        undecrypted = GetBody(msg)
                        decrypted = decrypt(undecrypted)
                        msg.set_payload(decrypted)

                all_msg.append(msg)
            except:
                print "Error: %s is a bad email" % msg['Subject']

        server.close()
        return all_msg

    return []

def GetBody(message):
    return message.get_payload(decode = True)
    
def ShowMinerResponces(messages = GetNewMinerEmail(__login__, __pass__)):
    reply = False
    for i in range(len(messages)):

        #if the signature does not match
        if CheckRecievingSignature(messages[i]) == False:
            continue
        else:
            print messages[i]['Subject'], "sent at", messages[i]['Date']
            print "\t", GetBody(messages[i])
            print 60 * '-'

            #we have replied at least once
            reply = True

    if reply == False:
        print "No new emails from miner"

    return

def CommandMiner(text_commands, ask_help = False):
    try:
        SendEmail(from_addr = email_from, to_addr_list = [email_to], cc_addr_list = [],
                  subject = email_command_subject if ask_help == False else email_command_subject_help, 
                  message = text_commands,
                  login = __login__,
                  password = __pass__)
        print "Sent Email!"
    except:
        print "Error: Could not send Email"
        
    return
    
def InvokeInput():
    all_text = []

    print "Email Contents to be Sent, [Ctrl-C to Send Email]"
    print "****IMPORTANT****\nBe sure to hit Enter after EVERY line you write, including the last one"
    print 60 * '_'

    #get user input until Keyboard Interupt
    while True:
        try:
            text = raw_input()
        except KeyboardInterrupt:
            #join with newlines
            return '\n'.join(all_text)

        all_text.append(text)

if __name__ == "__main__":
    if email_uniq_monitor_signature == email_uniq_commander_signature and email_from == email_to:
        print "Fatal Error: signatures cannot be the same when using the same email"
        sys.exit(1)

    #there must be atleast 1 argument
    if len(sys.argv) < 2:
        print "Requires at least 1 argument, use --help for help information"
        sys.exit(1)
    
    cli_arg = sys.argv[1]

    if cli_arg == "--help" or cli_arg == "-h":
        print "Usage:"
        print "\t--check or -c         Check for emails from the miner"
        print "\t--send or -s          Send a command email to the miner \n\t\t\t\t(Invokes built in text editor)"
        print "\t--sendhelp or -sh     Ask miner for help information"
    elif cli_arg == "--check" or cli_arg == "-c":
        ShowMinerResponces()
    elif cli_arg == "--send" or cli_arg == "-s":
        message = InvokeInput()
        #no input means the user changed his mind in sending email
        if message != "":
            print "\nSending Email ..."
            CommandMiner(message)
    elif cli_arg == "--sendhelp" or cli_arg == "-sh":
        CommandMiner("", True)
    else:
        print "Invalid command %s, use --help for help information" % sys.argv[1]

    print "Exited at", time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())


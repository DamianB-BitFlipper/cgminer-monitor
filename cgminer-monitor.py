#Copyright (c) 2013, Romain Dura romain@shazbits.com
#Copyright (c) 2014, John Smith slimcoin@anche.no

#
# cgminer-monitor
# John Smith | Contact: slimcoin@anche.no
# https://github.com/JSmith-BitFlipper/cgminer-monitor
# BTC 1AsxJdSafUdES2HvAZt2pnF7DiPeunBRKn
# LTC LVD6egk3rF8se2xNgwGgvJfyvSBU8VV3nX
# PPC PTKehuReGEASb6EyUYj1V7JEMz5M6DdBBU
# DOGE DJwTG3P4jG8ujKvwfhBV6Bps39nriU5Ty4
#

#
# If you find any bugs, please email me with the output and how you caused it
#
# In order to enable the cgminer API, append '--api-listen --api-allow W:127.0.0.1' to the command
# or add it in your cgminer.conf config file
#

# Additional Dependencies that may be needed: pycrypto

import socket
import sys
import time

import smtplib
import imaplib
import email
from email import parser

import json
import os
import threading

import SimpleHTTPServer
import SocketServer
import urllib2

#crypto stuff
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random

#
# Configurations
#

cgminer_host = 'localhost'
cgminer_port = 4028

#change if not using gmail
# the best way to find the sever addresses is to do a web search
# append the SSL or TSL port at the end
#script may crash if there is a port on imap, leave it without a port
email_smtp_server = 'smtp.gmail.com:587'
email_imap_server = 'imap.gmail.com'

email_login = 'login_username'
email_password = 'login_password'
email_from = 'example@email.com'
email_to = 'example@email.com'

###########IMPORTANT###########
#Be sure that the commander script has the same values for the these variables

#The same values for both variables CANNOT be used with the same email_from and email_to address

#all emails from this script will start with this
email_uniq_monitor_signature = 'Miner'

#all emails from the commander script will start with this
email_uniq_commander_signature = 'Commander'
###########IMPORTANT###########

#Subjects must be the same in cgminer-monitor script
email_command_subject = 'Do'  #subject of emails that contain commands to execute
email_command_subject_help = 'Help'  #subject of emails requesting help on the command email usage
email_internet_check_subject = "Internet_Status"  #subject of email containing the internet check information
email_warning_subject = 'Warning'  #subject of emails containing warnings

email_check_for_commands = True  #should the miner check for incomming email commands
email_command_check_interval = 10  #checks for new commands every 10 minutes

check_internet_connection = True  #should the miner check the internet connection
email_for_internet_check = True  #should the miner send emails for the internet connection status
email_internet_check_interval = 2  #email every 2 hours for internet checks
internet_retry_mins = 30  #If there is no internet connections, retry connection after 25 minutes

email_encrypt = True  #should outgoing mail be encrypted
email_decrypt = True  #should incomming mail commands be decrypted

#Be sure the encryption password matches the commander's decryption password and vice-vera
email_encrypt_key = b'Super Secure Passphrase Goes Here'  #encryption passphrase
email_decrypt_key = b'Super Secure Passphrase Goes Here'  #decryption passphrase 

monitor_interval = 15  #interval between a miner monitor check in seconds
monitor_wait_after_email = 60  #waits 60 seconds after the status email was sent
monitor_http_interface = '0.0.0.0'
monitor_http_port = 84
monitor_restart_cgminer_if_sick = True  #should cgminer restart if a gpu is sick/dead
monitor_send_email_alerts = True  #should emails be sent containing status information, etc.
monitor_max_temperature = 85  #maximum rate temperature before a warning is sent in Celcius
monitor_min_mhs_scrypt = 0.5  #minimum expected hash rate for scrypt, if under, warning is sent in MH/s
monitor_min_mhs_sha256 = 500  #minimum expected hash rate for sha256, if under, warning is sent in MH/s

monitor_enable_pools = False  #get balance from pools, not tested, might not work

n_gpus = 1  #The number of gpu's on the system


#
# Configurations
#


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

# MMCFE pools (www.wemineltc.com, dgc.mining-foreman.org, megacoin.miningpool.co, etc.)
# Replace the URLs and/or API keys by your own, add as many pools as you like
pools = [
    {
        'url': 'http://www.digicoinpool.com/api?api_key=1234567890',
        'cur': 'DGC'
    },
    {
        'url': 'http://www.wemineltc.com/api?api_key=1234567890',
        'cur': 'LTC'
    },
]


#
# Shared between monitor and http server
#

shared_output = ''
shared_output_lock = threading.Lock()


#
# For checking the internet connection
#

def internet_on():
    try:
        response = urllib2.urlopen('https://startpage.com/', timeout = 10)
        return True
    except urllib2.URLError as err: pass
    
    return False

#
# cgminer RPC
#

class CgminerClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def command(self, command, parameter):
        # sockets are one time use. open one for each command
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((self.host, self.port))
            if parameter:
                self._send(sock, json.dumps({"command": command, "parameter": parameter}))
            else:
                self._send(sock, json.dumps({"command": command}))
            received = self._receive(sock)
        except Exception as e:
            print e
            sock.close()
            return None

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        # the null byte makes json decoding unhappy
        try:
            decoded = json.loads(received.replace('\x00', ''))
            return decoded
        except:
            pass # restart makes it fail, but it's ok

    def _send(self, sock, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def _receive(self, sock, size=65500):
        msg = ''
        while True:
            chunk = sock.recv(size)
            if chunk == '':
                # end of message
                break
            msg = msg + chunk
        return msg


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

#
# Utils
#

def CheckSignature(message, signature):
    words = message['Subject'].split('_')

    if words == []:
        return False

    #first word in subject must be the uniq_signature from the miner
    if words[0] != signature:
        return False

    return True

def SubjectWithoutSignature(message, signature):
    if CheckSignature(message, signature) == False:
        return ""

    words = message['Subject'].split('_')
    #take out the first element, the signature
    words = words[1:]
    #rejoin everything together
    return ''.join(words)


def SendEmail(from_addr, to_addr_list, cc_addr_list,
              subject, message, login, password,
              smtpserver = email_smtp_server):
    header = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Cc: %s\n' % ','.join(cc_addr_list)
    header += 'Subject: %s\n\n' % (email_uniq_monitor_signature + '_' + subject)

    #encrypt the message
    if email_encrypt == True:
        message = encrypt(message)

    server = smtplib.SMTP(smtpserver)
    server.starttls()
    server.login(login, password)
    server.sendmail(from_addr, to_addr_list, header + message)
    server.quit()

        
def GetNewEmails(login, password, imapserver = email_imap_server):
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

            #only mark new messages from the commander as seen, else unmark them
            if CheckSignature(msg, email_uniq_commander_signature) == True:
                typ, data = server.store(num, '+FLAGS', '(\\Seen)')
            else:
                #mark the email as unseen 
                typ, data = server.store(num, '-FLAGS', '(\\Seen)')

            try:
                if CheckSignature(msg, email_uniq_commander_signature) == True:
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

def ParseBody(text):
    text = text.split(';')
    parsed = []
    #indexes of elements to be removed
    to_be_removed = []
    
    for i in range(len(text)):
        parsed.append(text[i].split(','))

        #in each element of this parsed text, remove extrenous chars like spaces, \t, \n, \r, etc
        for b in range(len(parsed[i])):
            parsed[i][b] = ''.join(parsed[i][b].split())

        #remove blank lists
        if parsed[i] == [''] or parsed == []:
            to_be_removed.append(i)

    #since we are removing elements, the elements to be removed go down by the number we have already removed
    removed = 0
    for i in range(len(to_be_removed)):
        del parsed[to_be_removed[i - removed]]
        removed += 1

    return parsed

def ApplyMessageCommands(messages, client, output, must_send_email):
    for i in range(len(messages)):
        #apply commands from last to first
        msg = messages[-i]

        #if the subject is asking for syntax help
        if SubjectWithoutSignature(msg, email_uniq_commander_signature) == email_command_subject_help:
            help_info = """command, parameter; or command;
                           \tExample: gpu, 0;\n gpuintensity, 0, 13;
                           See the cgminer API-README for commands\n"""

            SendEmail(from_addr = email_from, to_addr_list = [email_to], cc_addr_list = [],
                      subject = "Returning " + email_command_subject_help,
                      message = help_info,
                      login = email_login,
                      password = email_password)
            
            continue


        #make sure it is a command message
        if SubjectWithoutSignature(msg, email_uniq_commander_signature) != email_command_subject:
            continue

        try:
            reply = ''
            parsed = ParseBody(GetBody(msg))
            for i in range(len(parsed)):
                #append all args but the first one together
                if len(parsed[i]) > 1:
                    parsed[i][1] = ', '.join(parsed[i][1:])
                    del parsed[i][2:]

                #print "Parsed:", parsed[i]
                
                #must have a command
                if parsed[i][0] == '' or parsed[i][0] == None:
                    output + "Element %d must have a command\n" % i
                    must_send_email = True
                    continue

                result = client.command(parsed[i][0], parsed[i][1] if len(parsed[i]) > 1 else None)

                if result:
                    reply += "Command: " + parsed[i][0] + " " + \
                             (parsed[i][1] + "\n") if len(parsed[i]) > 1 else "\n"
                    reply += str(result) + "\n"

            #if it has a reply, email it
            if reply != '':
                SendEmail(from_addr = email_from, to_addr_list = [email_to], cc_addr_list = [],
                          subject = "Returning " + email_command_subject,
                          message = reply,
                          login = email_login,
                          password = email_password)
        except:
            output += "Not A valid E-mail Body\n\t %s\n" % GetBody(msg)
            must_send_email = True

    return


#
# Monitor
#

def StartMonitor(client):
    os.system('clear')

    #time internet was lost and reconnected
    internet_lost = 0
    internet_reconnected = 0

    test_internet_connection = False

    last_command_check = time.time()
    last_internet_check = time.time()
    last_internet_check_email_sent = time.time()
    
    while(1):
        output = ''

        must_send_email = False
        must_restart = False

        #check the internet connection every email_internet_check_interval minutes
        if (time.time() - last_internet_check > email_internet_check_interval * 60 * 60 \
            or test_internet_connection == True) and \
            check_internet_connection == True:

            last_internet_check = time.time()
            
            #test the internet connection
            if internet_on() == False:
                if internet_lost == 0:
                    internet_lost = time.time()

                #turn off the gpu miners
                for loop in range(n_gpus):
                    client.command('gpudisable', str(loop))

                #sleep N mins before retrying
                time.sleep(internet_retry_mins * 60)

                #do not wait for the timer, we WANT to test the connection
                test_internet_connection = True

                #if there is still no internet, do not bother turning them back on
                if internet_on() == True:
                    internet_reconnected = time.time()
                    output += "Internet connection lost for %d seconds\n\tTime when connection lost %d (epoch)\n\tTime when reconnected %d (epoch)\n" % (internet_reconnected - internet_lost, internet_lost, internet_reconnected)
                    
                    #make sure it sends an email
                    must_send_email = True
                    
                    #reset the internet lost time
                    internet_lost = 0
                    test_internet_connection = False

                    #Start them miners up!
                    for loop in range(n_gpus):
                        client.command('gpuenable', str(loop))
                        
                continue

        result = client.command('coin', None)
        coin = ''
        if result:
            coin = result['COIN'][0]['Hash Method']
            output += 'Coin     : %s\n' % coin


        result = client.command('pools', None)
        if result:
            output += 'Pool URL : %s\n' % (result['POOLS'][0]['Stratum URL'])
            warning = ' <----- /!\\' if result['POOLS'][0]['Status'] != 'Alive' else ''
            must_send_email = True if warning != '' else must_send_email
            output += 'Pool     : %s%s\n' % (result['POOLS'][0]['Status'], warning)

        for loop in range(n_gpus):
            result = client.command('gpu', str(loop))
            if result:
                gpu_result = result['GPU'][0]
                warning = ' <----- /!\\' if gpu_result['Status'] != 'Alive' else ''
                must_restart = True if warning != '' else False
                must_send_email = True if warning != '' else must_send_email
                output += 'GPU %d    : %s%s\n' % (int(loop), gpu_result['Status'], warning)

                min_mhs = monitor_min_mhs_scrypt if coin == 'scrypt' else monitor_min_mhs_sha256
                warning = ' <----- /!\\' if gpu_result['MHS 5s'] < min_mhs else ''
                must_send_email = True if warning != '' else must_send_email
                output += 'MHS 5s/av: %s/%s%s\n' % (gpu_result['MHS 5s'], gpu_result['MHS av'], warning)

                warning = ' <----- /!\\' if gpu_result['Temperature'] > monitor_max_temperature else ''
                must_send_email = True if warning != '' else must_send_email
                output += 'Temp     : %s%s\n' % (gpu_result['Temperature'], warning)
                output += 'Intensity: %s\n' % gpu_result['Intensity']

        result = client.command('summary', None)
        if result:
            if result['SUMMARY'][0]['Hardware Errors'] > 0:
                must_send_email = True
                output += 'HW err  : %s%s\n' % (result['SUMMARY'][0]['Hardware Errors'], ' <----- /!\\')

        result = client.command('stats', None)
        if result:
            uptime = result['STATS'][0]['Elapsed']
            output += 'Uptime   : %02d:%02d:%02d\n' % (uptime / 3600, (uptime / 60) % 60, uptime % 60)

        #check the email for new commands (work around for non-ssh remote commanding)
        if email_check_for_commands == True:
            if time.time() - last_command_check > email_command_check_interval * 60:
                last_command_check = time.time()
                ApplyMessageCommands(GetNewEmails(email_login, email_password), client, output, must_send_email)

        #sends emails periodically to test for the connection
        if email_for_internet_check == True:
            if time.time() - last_internet_check_email_sent > email_internet_check_interval * 60 * 60:
                last_internet_check_email_sent = time.time()
                SendEmail(from_addr = email_from, to_addr_list = [email_to], cc_addr_list = [],
                          subject = email_internet_check_subject + "at" + \
                          time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()),                          
                          message = output,
                          login = email_login,
                          password = email_password)
                
        print output

        global shared_output
        global shared_output_lock
        shared_output_lock.acquire()
        shared_output = output
        shared_output_lock.release()

        if must_restart and monitor_restart_cgminer_if_sick:
            print 'Restarting'
            result = client.command('restart', None)

        if must_send_email and monitor_send_email_alerts and uptime > 10:
            SendEmail(from_addr = email_from, to_addr_list = [email_to], cc_addr_list = [],
                      subject = email_warning_subject,
                      message = output,
                      login = email_login,
                      password = email_password)
            
            time.sleep(monitor_wait_after_email)

        # Sleep by increments of 1 second to catch the keyboard interrupt
        for i in range(monitor_interval):
            time.sleep(1)


        os.system('clear')

    return

#
# HTTP server request handler
#

class CGMinerRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

        if self.path == '/favicon.ico':
            return

        self.send_header("Content-type", "text/html")
        self.end_headers()

        global shared_output
        global shared_output_lock
        shared_output_lock.acquire()
        html_output = shared_output[:-1] # one too many \n
        shared_output_lock.release()

        # Get balance from pools
        pools_output = ''
        if monitor_enable_pools:
            td_div = '<td style="padding:8px; padding-left:10%; border-top:1px solid #dddddd; background-color:#ff6600; line-height:20px;">'
            for pool in pools:
                try:
                    response = urllib2.urlopen(pool['url'])
                    data = json.load(response)
                    pools_output += '\n</td></tr>\n<tr>' + td_div + '\n' + 'pool' + '</td>' + td_div + pool['cur'] + ' %.6f' % (float(data['confirmed_rewards']))
                except urllib2.HTTPError as e:
                    pools_output += '\n</td></tr>\n<tr>' + td_div + '\n' + 'pool' + '</td>' + td_div + pool['cur'] + ' Error: ' + str(e.code)
                except urllib2.URLError as e:
                    pools_output += '\n</td></tr>\n<tr>' + td_div + '\n' + 'pool' + '</td>' + td_div + pool['cur'] + ' Error: ' + e.reason
                except:
                    pools_output += '\n</td></tr>\n<tr>' + td_div + '\n' + 'pool' + '</td>' + td_div + pool['cur'] + ' Error: unsupported pool?'

        # Format results from the monitor
        td_div = '<td style="padding:8px; padding-left:10%; border-top:1px solid #dddddd; line-height:20px;">'
        html_output = ('\n</td></tr>\n<tr>' + td_div + '\n').join(html_output.replace(': ', '</td>' + td_div).split('\n'))
        html_output += pools_output
        html = """
        <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>cgminer monitor</title>
            </head>
            <body style="margin:0; font-family:Helvetica Neue,Helvetica,Arial,sans-serif;">
                <table style="vertical-align:middle; max-width:100%; width:100%; margin-bottom:20px; border-spacing:2px; border-color:gray; font-size:small; border-collapse: collapse;">
                    <tr><td style="padding:8px; padding-left:10%; border-top:1px solid #dddddd; line-height:20px;">
        """ + html_output + """
                    </td></tr>
                </table>
            </body>
        </html>
        """
        self.wfile.write(html)


# """
# Usage: cgminer-monitor.py [command] [parameter]
#
# Script will need to open a socket, so running in super-user mode may be needed
#
# No arguments: monitor + http server mode. Press CTRL+C to stop.
# Arguments: send the command with optional parameter and exit.
#

# Useful error translations:
# [Errno 111] Connection refused - cgminer's API has not been started yet
#       Solution: Be sure to run cgminer with '--api-listen --api-allow W:127.0.0.1'
#
# [Errno 107] Transport endpoint is not connected
#       Solution: Check that the --api-allow address is correct
#
# [Errno -2] Name or service not known
#       Solution: Make sure your imap and smtp server locaions are correct
#                     The script may crash if there is a port on the imap server, leave it without a port


if __name__ == "__main__":
    if email_uniq_monitor_signature == email_uniq_commander_signature and email_from == email_to:
        print "Fatal Error: signatures cannot be the same when using the same email"
        sys.exit(1)

    command = sys.argv[1] if len(sys.argv) > 1 else None
    parameter = sys.argv[2] if len(sys.argv) > 2 else None

    client = CgminerClient(cgminer_host, cgminer_port)

    if command:
        # An argument was specified, ask cgminer and exit
        result = client.command(command, parameter)
        print result if result else 'Cannot get valid response from cgminer'
    else:
        # No argument, start the monitor and the http server
        try:
            #check if the encryption ket is a good size
            if email_encrypt == True:
                if len(email_encrypt_key_hash) != 32:
                    print "Error: Hashing function does not output a 32 byte string"
                    sys.exit(1)

            #check if the encryption ket is a good size
            if email_decrypt == True:
                if len(email_decrypt_key_hash) != 32:
                    print "Error: Hashing function does not output a 32 byte string"
                    sys.exit(1)

            server = SocketServer.TCPServer((monitor_http_interface, monitor_http_port), CGMinerRequestHandler)
            threading.Thread(target = server.serve_forever).start()

            #start the monitor
            StartMonitor(client)

        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(0)

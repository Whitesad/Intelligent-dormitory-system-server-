import socket
import threading
import json
import datetime
import time

import pymysql
import threadpool
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64


user={}
# FTPUserName=""
# FTPPassWord=""


class User:
    def __init__(self,username="",password="",publickey="",con=socket.socket()):
        self.username=username
        self.password=password
        self.publickey=publickey
        self.RsaMaker=RSAMaker()
        self.con=con
        self.isDecrypt=False
    def setUserName(self,username):
        self.username=username
    def setPassWord(self,password):
        self.password=password
    def setPublicKey(self,publickey):
        self.publickey=publickey
        try:
            self.RsaMaker.SetClientPublicKey(publickey)
        except Exception as e:
            print(str(e))

    def setConnect(self,con):
        self.con=con

    def getUserName(self):
        return self.username
    def getPassWord(self):
        self.password
    def getPublicKey(self):
        self.publickey

class RSAMaker:
    def __init__(self):
        pass

    def SetClientPublicKey(self,publickey):
        try:
            self.__ClientPublicKey=publickey
            self.__ClientRsakey = RSA.importKey(self.__ClientPublicKey)
            self.__ClientCipher = Cipher_pkcs1_v1_5.new(self.__ClientRsakey)
        except:
            raise Exception('PublicKey import error!')

    def Encrypt(self,content):
        return str(base64.b64encode(self.__ClientCipher.encrypt(bytes(content,encoding='utf8'))),encoding='utf8')

    def Decrypt(self,content):
        # rsakey=RSA.importKey(self.__private_pem)
        # cipher = Cipher_pkcs1_v1_5.new(rsakey)
        # text = cipher.decrypt(base64.b64decode(content), self.__random_generator)
        text = self.__cipher.decrypt(base64.b64decode(content), self.__random_generator)
        text=str(text,encoding='utf8')
        return text

    def CreateRSAKey(self):
        # 伪随机数生成器
        self.__random_generator = Random.new().read
        # rsa算法生成实例
        self.__rsa = RSA.generate(1024, self.__random_generator)

        # master的秘钥对的生成
        self.__private_pem = self.__rsa.exportKey()
        print('Successfully create the privatekey!')
        self.public_pem = self.__rsa.publickey().exportKey()
        print('Successfully create the publickey!')
        self.__rsakey = RSA.importKey(self.__private_pem)
        self.__cipher = Cipher_pkcs1_v1_5.new(self.__rsakey)


class Sock():
    hostName = ''
    hostIp = ''
    port = 50000
    sqlPasswd = ''

    __userDict__ = {}
    __mesQueue__ = []

    def __MakeTextDict__(self,dict_dict):
        dict_dict["time"] = datetime.datetime.now().strftime('%H:%M:%S')
        return dict_dict

    def __init__(self):
        self.hostName = socket.gethostname()
        self.hostIp = socket.gethostbyname(self.hostName)
        # socket.AF_INET, socket.SOCK_STREAM
        self.__socketServer__ = socket.socket()
        print('Socket ' + self.hostName + ' create')
        self.__socketServer__.bind((self.hostIp, self.port))
        self.__socketServer__.listen(10)
        print('Socket ' + self.hostIp + ' new listening')

        self.__rsaMaker=RSAMaker()
        self.__rsaMaker.CreateRSAKey()

        self.__chatTheradPool__ = threadpool.ThreadPool(25)
        self.__sendThreadPool__ = threadpool.ThreadPool(25)
        # con=socket.socket()
        # requests = threadpool.makeRequests(self.__Thread_Listen__, [([self, con], {})])
    def close(self):
        self.SockSQL.close()
        print('Close the database')

    def setHostIp(self, hostIp):
        self.hostIp = hostIp

    def setSQLPasswd(self, passWd):
        self.sqlPasswd = passWd

    def startServer(self):
        self.SockSQL = pymysql.connect(host='127.0.0.1', user='root', password=self.sqlPasswd, db='socketsql',
                                       charset='utf8', port=3306)
        print('user:root socketSQL 连接成功')

        print("本地socket服务：" + str(self.__socketServer__))
        while True:
            con, addr = self.__socketServer__.accept()  # recieve connect,addr includes ip and port
            print('Connect ' + addr[0] + ':' + str(addr[1]) + " Try to Connect")
            user=User(con=con)
            threading.Thread(target=self.__SendPublicKey__,args=(user,)).start()

    def __BroadCast__(self, dict_dict):
        for username, user_list in self.__userDict__.items():
            for user in user_list:
                self.__Send__(user , user.con, self.__MakeTextDict__(dict_dict))

    def __Thread_Listen__(self, user):
        username = user.username
        con = user.con
        while True:
            try:
                dict_dict = self.__Receive__(user,con)
                if ( "type" in dict_dict.keys() and dict_dict["type"] == "TEXT_MES"):
                    self.__RecordMes__(dict_dict)
                    threading.Thread(target=self.__BroadCast__, args=(dict_dict,)).start()
                    print('receive:' + str(dict_dict))
            except:
                self.__Close__(user)
                return

    def __Register__(self, dict_dict):
        query = 'SELECT * FROM normaluser where username="%s"'
        result_dict = self.__SQL_QUERY__(query % dict_dict['username'])
        if (not result_dict):
            insert = 'INSERT INTO normaluser values ("%s","%s")'
            if (self.__SQL_INSERT__(insert % (dict_dict['username'], dict_dict['password']))):
                return 'AC'
            else:
                return 'REGISTER_ERROR'
        else:
            status = 'SAME_NAME'
        return status

    def __StartChatThread__(self, user):
        username=user.username
        con=user.con
        # con.setblocking(0)
        if(username in self.__userDict__.keys()):
            self.__userDict__[username].append(user)
        else:
            self.__userDict__[username]=[user]

        threading.Thread(target=self.__Thread_Listen__, args=(user,)).start()
        # requests=threadpool.makeRequests(self.__Thread_Listen__, [([con],None)] )
        # for req in requests:
        #     self.__chatTheradPool__.putRequest(req)

    def __Check_Memship__(self, dict_dict):
        query = 'SELECT * FROM normaluser where username="%s"'
        result = ''
        result_dict = {}
        print('query:' + query % dict_dict['username'])
        try:
            result_dict = self.__SQL_QUERY__(query % dict_dict['username'])
            print('query result:')
            print(result_dict)
            if (not result_dict):
                result = 'NO_MEMSHIP'
            else:
                if (result_dict['password'] == dict_dict['password']):
                    result = 'AC'
                else:
                    result = 'WRONG_PASSWORD'
        except:
            result = 'QUERY_ERROR'
            print('QUERY_ERROR!')
        return result

    def __SendPublicKey__(self,user):
        time.sleep(0.1)
        dict_request=self.__Receive__(user,user.con)
        if("type" in dict_request.keys() and dict_request["type"]=="LOGIN_REQUEST"):
            user.setPublicKey(dict_request['publickey'])
            self.__Send__(user ,user.con,{"type":"publickey","publickey":str(self.__rsaMaker.public_pem,encoding='ascii')[2:-1]})
        time.sleep(0.5)
        self.__LoginReq__(user)


    def __LoginReq__(self, user):
        con=user.con
        try:
            dict_mes = self.__Receive__(user,con)
        except:
            return
        loginResult = 'None'
        if (dict_mes['type'] == 'LOGIN_MES'):
            if (dict_mes['status'] == 'login'):
                result = self.__Check_Memship__(dict_mes)
                if (result == 'AC'):
                    print('user ' + dict_mes['username'] + ' Login AC' + ' ip: ' + dict_mes['ip'])

                    user.setUserName(dict_mes['username'])
                    user.setPassWord(dict_mes['password'])

                    self.__StartChatThread__(user)
                    self.__Send__(user ,con, {'type': 'LOGIN_MES', 'status': 'AC',"ftpusername":FTPUserName,"ftppassword":FTPPassWord})
                    loginResult = 'LOGIN_AC'
                elif (result == 'WRONG_PASSWORD'):
                    self.__Send__(user ,con, {'type': 'LOGIN_MES', 'status': 'WRONG_PASSWORD'})
                    loginResult = 'WRONG_PASSWORD'
                elif (result == 'NO_MEMSHIP'):
                    self.__Send__(user ,con, {'type': 'LOGIN_MES', 'status': 'NO_MEMSHIP'})
                    loginResult = 'NO_MEMSHIP'
                elif (result == 'QUERY_ERROR'):
                    self.__Send__(user ,con, {'type': 'LOGIN_MES', 'status': 'QUERY_ERROR'})
                    loginResult = 'QUERY_ERROR'
        elif (dict_mes['type'] == 'REGISTER_MES'):
            if (dict_mes['status'] == 'register'):
                result = self.__Register__(dict_mes)
                if (result == 'AC'):
                    self.__Send__(user ,con, {'type': 'REGISTER_MES', 'status': 'AC'})
                    loginResult = 'REGISTER_AC'
                elif (result == 'SAME_NAME'):
                    self.__Send__(user ,con, {'type': 'REGISTER_MES', 'status': 'SAME_NAME'})
                    loginResult = 'SAME_NAME'
                elif (result == 'REGISTER_ERROR'):
                    self.__Send__(user ,con, {'type': 'REGISTER_MES', 'status': 'REGISTER_ERROR'})
                    loginResult = 'REGISTER_ERROR'
        if (loginResult != 'LOGIN_AC'):
            print(loginResult)
            con.close()
        return loginResult

    def __Decrypt__(self,dict_dict):
        if ('login' in dict_dict.keys()):
            dict_dict["username"] = self.__rsaMaker.Decrypt(dict_dict["username"])
            dict_dict['password'] = self.__rsaMaker.Decrypt(dict_dict['password'])
        if ('username' in dict_dict.keys()):
            dict_dict["username"] = self.__rsaMaker.Decrypt(dict_dict["username"])
        if ('password' in dict_dict.keys()):
            dict_dict['password'] = self.__rsaMaker.Decrypt(dict_dict['password'])
        if ('content' in dict_dict.keys()):
            dict_dict['content'] = self.__rsaMaker.Decrypt(dict_dict['content'])
        if ('publickey' in dict_dict.keys()):
            dict_dict['publickey'] = dict_dict['publickey'].replace('*', '\n')
    def __Receive__(self,user, con):
        try:
            dict_bytes = con.recv(2048)
            dict_dict = json.loads(str(dict_bytes, encoding='utf8'))
            self.__Decrypt__(dict_dict)
            return dict_dict
        except:
            raise Exception('Receive Error!')

    def __Encrypt__(self,dict,user):
        if("content"in dict.keys()):
            dict['content']=user.RsaMaker.Encrypt(dict['content'])
        if('ftpusername'in dict.keys()):
            dict['ftpusername'] = user.RsaMaker.Encrypt(dict['ftpusername'])
        if ('ftppassword' in dict.keys()):
            dict['ftppassword'] = user.RsaMaker.Encrypt(dict['ftppassword'])
    def __Send__(self,user, sock, dict):
        self.__Encrypt__(dict,user)
        try:
            bytes_mes = bytes(json.dumps(dict), encoding='utf8')
            sock.send(bytes_mes)
            print("send dict to " + str(sock))
            print(str(dict) + "\n")

        except:
            print('Send to '+str(sock)+' Error!')
            raise Exception('Send Error!')

    def __Close__(self,user):
        username=user.username
        con=user.con
        con.close()
        print("Connect has closed")
        if(username in self.__userDict__.keys()):
            user_list=self.__userDict__[username]
            if(user in user_list):
                user_list.remove(user)
                print("user "+username+" has removed")
                if(len(user_list)==0):
                    self.__userDict__.pop(username)
                    print(username+" exits completely")

    def __RecordMes__(self,dict_text):
        keys=dict_text.keys()
        try:
            if('localname' in keys and 'username' in keys and 'content' in keys):
                cur_time = datetime.datetime.now()
                date = str(cur_time.year) + '-' + str(cur_time.month) + '-' + str(cur_time.day)
                time = str(cur_time.hour) + ':' + str(cur_time.minute) + ':' + str(cur_time.second)
                insert = 'INSERT INTO record_test values ("{date}","{time}","{device}","{username}","{content}");'.format(
                    date=date, time=time, device=dict_text['localname'], username=dict_text['username'],
                    content=dict_text['content'])
                self.__SQL_INSERT__(insert)
            else:
                raise Exception('Format Error!')
            return
        except:
            print('Record Error')


    def __SQL_INSERT__(self, string):
        cursor = self.SockSQL.cursor()
        status = False
        try:
            cursor.execute(string)
            self.SockSQL.commit()
            status = True
        except:
            self.SockSQL.rollback()
            status = False
        cursor.close()
        return status

    def __SQL_QUERY__(self, string):
        cursor = self.SockSQL.cursor(cursor=pymysql.cursors.DictCursor)
        cursor.execute(string)
        dict_list = cursor.fetchall()
        cursor.close()
        if (not dict_list):
            return {}
        else:
            return dict(dict_list[0])


def fun(string):
    print(string)
    pool = threadpool.ThreadPool(10)
    requests = threadpool.makeRequests(fun, ["whitesad"])
    for req in requests:
        pool.putRequest(req)
    pool.wait()
    threadpool.WorkRequest

if __name__ == "__main__":
    socketServer=object
    try:
        config=open('config.conf')
        str_config=""
        for line in config:
            str_config+=line.strip()
        str_config.replace("\n",'')
        global FTPPassWord
        global FTPUserName
        dict_config=json.loads(str_config)
        FTPPassWord=dict_config['ftppassword']
        FTPUserName=dict_config['ftpusername']
        socketServer = Sock()
        socketServer.setSQLPasswd(dict_config['sqlpassword'])
        socketServer.startServer()
    except IOError:
        print('config.conf does not exists!')
    finally:
        config.close()
        socketServer.close()


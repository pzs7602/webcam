import cv2
import time
import threading
from flask import Flask, request, Response, jsonify, make_response, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime
from functools import wraps
import json
import requests
from string import Template
import sys
import signal
# for control-c capture
def handler(signal, frame):
  global video_capture
  print('CTRL-C pressed!', file=sys.stdout)
  video_capture.release()
  video_capture = None
  sys.exit(0)

signal.signal(signal.SIGINT, handler)
#signal.pause()

'''
JWT 验证实现
访问特定URL 时需要验证(由route 下的 @token_required)， 如：/user，此时会定向到 render_template('login.html')
/login 获取表单的 username/password 后，与users 表进行比对，如一致则设置指定时效有效的 jwt 字串，经 jwt.encode 后获得 jwt token，
将此 tooken 置于 session 中，此后即可在 session 中获取 jwt token
token_required 方法在 session 中取 token，若无，则定向到 login.html 进行登录；若有，则将 token 解码后获取用户信息返回。request 请求中若有 authentication header，
则或缺其中的 x-access-tokens 为 token

ATTENTON pip install PyJWT==1.7.1

'''
# Create the Flask object for the application
app = Flask(__name__)

app.config['SECRET_KEY']='YOUR_SECRET_KEY_HERE'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///./users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   

class Users(db.Model):  
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)  
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)
  token = db.Column(db.String(200))
  
class Authors(db.Model):  
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(50), unique=True, nullable=False)   
  book = db.Column(db.String(20), unique=True, nullable=False) 
  country = db.Column(db.String(50), nullable=False)  
  booker_prize = db.Column(db.Boolean) 
  user_id = db.Column(db.Integer)

# Image frame sent to the Flask object
global video_frame
video_frame = None

# Use locks for thread-safe viewing of frames in multiple browsers
global thread_lock 
thread_lock = threading.Lock()

# GStreamer Pipeline to access the Raspberry Pi camera
GSTREAMER_PIPELINE = 'nvarguscamerasrc ! video/x-raw(memory:NVMM), width=3280, height=2464, format=(string)NV12, framerate=21/1 ! nvvidconv flip-method=0 ! video/x-raw, width=960, height=616, format=(string)BGRx ! videoconvert ! video/x-raw, format=(string)BGR ! appsink wait-on-eos=false max-buffers=1 drop=True'

def token_required(f):  
   @wraps(f)  
   def decorator(*args, **kwargs):
#      token = None
      # havent login 
      try:
         token = session["token"]
      except:
         return render_template('login.html')
      if 'x-access-tokens' in request.headers:  
         token = request.headers['x-access-tokens'] 

      if not token:
         #return jsonify({'message': 'a valid token is missing'})   
         return render_template('login.html')

      try: 
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()  
      except Exception as e:
         print(f'exception message={str(e)}', file=sys.stdout)
         return render_template('login.html')
#         return jsonify({'exception message': str(e)})  

      return f(current_user, *args,  **kwargs)  
   return decorator    

def captureFrames():
    global video_frame, thread_lock, video_capture

    # Video capturing from OpenCV
    video_capture = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
    # 程序运行后使改循环永久进行，以便处理 stop/start 功能。 start 只是继续 encodeFrame
    while True :
        if not video_capture.isOpened():
#          print(f'video_capture.isCloseed')
          continue
        return_key, frame = video_capture.read()
        # if read to the end, reture_key is Flase
        # if not return_key:
        #     print(f'break')
        #     break
        if frame is None:
          continue

#        print(f'video frame copied')
        video_frame = frame.copy()
        # Create a copy of the frame and store it in the global variable,
        # with thread safe access
        # 以下代码
        # with thread_lock:
        #     print(f'video frame copied')
        #     video_frame = frame.copy()
        
        # key = cv2.waitKey(0) & 0xff
        # if key == 27:
        #     break

    video_capture.release()
        
def encodeFrame():
    global thread_lock
    while True:
        # Acquire thread_lock to access the global video_frame object
        with thread_lock:
            global video_frame
            if video_frame is None:
                print(f'video_frame is None')
                continue
            return_key, encoded_image = cv2.imencode(".jpg", video_frame)
            if not return_key:
                continue

        # Output image as a byte array
        yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + 
            bytearray(encoded_image) + b'\r\n')

# 捕获开始后，如果直接访问本页面，只显示静态图像，不会刷新（HTML是无连接协议)。请访问 /start 获取实时视频
@app.route("/")
@token_required
def streamFrames(current_user):
    # if video_capture is None:
    #   print(f're-create video_capture')
    #   video_capture = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
    return Response(encodeFrame(), mimetype = "multipart/x-mixed-replace; boundary=frame")

@app.route("/video")
@token_required
def video(current_user):
    vidtemplate = """
      <h2>
        Operation: 
        <a href="/stop">Stop</a>
      </h2>
    
      <iframe src="/" width="853" height="480" frameborder="0" allowfullscreen></iframe>
    """

    return vidtemplate


@app.route("/stop")
@token_required
def stop_capture(current_user):
    global video_capture, isOpened
    video_capture.release()
    isOpened = False
    vidtemplate = """
      <h2>
        Operation: 
        <a href="/start">Start</a>
      </h2>
    
      <iframe src="/" width="960" height="616" frameborder="0" allowfullscreen></iframe>
    """

    return vidtemplate

#    return jsonify({'message': 'video capture stopped'}) 

@app.route("/start")
@token_required
def start_capture(current_user):
    # Video capturing from OpenCV
    global video_capture, isOpened
    try:
      if not isOpened:
        video_capture = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
        isOpened = True
        print(f'closed, start', file=sys.stdout)
      else:
        print(f'already started', file=sys.stdout)
    except:
      video_capture = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
      print(f'except, start', file=sys.stdout)
    vidtemplate = """
      <h2>
        Operation: 
        <a href="/stop">Stop</a>
      </h2>
    
      <iframe src="/" width="960" height="616" frameborder="0" allowfullscreen></iframe>
    """

    return vidtemplate

#    return jsonify({'message': 'video capture started'}) 

@app.route('/login', methods=['POST'])
def login_user(): 
 
#  auth = request.authorization   
  name = request.form['username']
  password = request.form['password']
  
#   if not auth or not auth.username or not auth.password:  
#      return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

  user = Users.query.filter_by(name=name).first()   

  if check_password_hash(user.password, password): 
     # will expire 2 days
     token_str = {'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60*24*2)}
     token = jwt.encode(token_str, app.config['SECRET_KEY']) 
     user.token = token
     db.session.commit()   
     session['token'] = token

#     return jsonify({'token' : token.decode('UTF-8'),'token_str': token_str}) 
     return redirect('/start')
  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


# check to see if this is the main thread of execution
if __name__ == '__main__':
    # video_capture.isOpened 不知为何有时在停止捕获后仍为 True，故设置改变量保存相机开启/关闭状态
    global isOpened
    # Create a thread and attach the method that captures the image frames, to it
    process_thread = threading.Thread(target=captureFrames)
    isOpened = True
    process_thread.daemon = True

    # Start the thread
    process_thread.start()

    # start the Flask Web Application
    # While it can be run on any feasible IP, IP = 0.0.0.0 renders the web app on
    # the host machine's localhost and is discoverable by other machines on the same network 
    app.run("0.0.0.0", port="8000")

    
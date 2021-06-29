import cv2
import time
import argparse
import threading
from flask import Flask, request, Response, jsonify, make_response, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime
from functools import wraps
import json
import numpy as np
import requests
from string import Template
from PIL import Image
from utils.yolo_classes import get_cls_dict
from utils.camera import add_camera_args, Camera
from utils.display import open_window, set_display, show_fps
from utils.visualization import BBoxVisualization
from utils.yolo_with_plugins import TrtYOLO
import pycuda.autoinit

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
initial user zhu, password zhuzhu. this is used for register active user. after user registered, delete the initial user from users table for security
token for user zhu
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiIwNTY2YjgwYy0zMDFmLTQzZjItOGQ2Mi1kMjQ4NzEyNWExZmYiLCJleHAiOjE2MjQ2NzYzMTd9.ZrK-UQk-YSFIcMiBLwCCS9JkaZ21LG7vm-6y75KsYnY"
token for user pzs
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiIyZDU3ZmY0ZC04MGYwLTQ0MjYtYWFlOC1jNmUxMWIwNmM5MmQiLCJleHAiOjE2MjQ2NzY0NzZ9.35G9pdqjeK1tbe-x1CsXTRXziuspyhwgusqQF9gUFik"

'''
def gstreamer_pipeline(
    capture_width=1280,
    capture_height=720,
    display_width=1280,
    display_height=720,
    framerate=60,
    flip_method=0,
):
    return (
        "nvarguscamerasrc ! "
        "video/x-raw(memory:NVMM), "
        "width=(int)%d, height=(int)%d, "
        "format=(string)NV12, framerate=(fraction)%d/1 ! "
        "nvvidconv flip-method=%d ! "
        "video/x-raw, width=(int)%d, height=(int)%d, format=(string)BGRx ! "
        "videoconvert ! "
        "video/x-raw, format=(string)BGR ! appsink"
        % (
            capture_width,
            capture_height,
            framerate,
            flip_method,
            display_width,
            display_height,
        )
    )


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

def parse_args():
    """Parse input arguments."""
    desc = ('Capture and display live camera video, while doing '
            'real-time object detection with TensorRT optimized '
            'YOLO model on Jetson')
    parser = argparse.ArgumentParser(description=desc)
    parser = add_camera_args(parser)
    # where action='store_true' implies default=False.
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='show deteced class and bbox')
    args = parser.parse_args()
    return args

def check_rotation(path_video_file):
     # this returns meta-data of the video file in form of a dictionary
     meta_dict = ffmpeg.probe(path_video_file)

     # from the dictionary, meta_dict['streams'][0]['tags']['rotate'] is the key
     # we are looking for
     rotateCode = None
     if int(meta_dict['streams'][0]['tags']['rotate']) == 90:
         rotateCode = cv2.ROTATE_90_CLOCKWISE
     elif int(meta_dict['streams'][0]['tags']['rotate']) == 180:
         rotateCode = cv2.ROTATE_180
     elif int(meta_dict['streams'][0]['tags']['rotate']) == 270:
         rotateCode = cv2.ROTATE_90_COUNTERCLOCKWISE

     return rotateCode

def rotate_image(image, angle):
  image_center = tuple(np.array(image.shape[1::-1]) / 2)
  rot_mat = cv2.getRotationMatrix2D(image_center, angle, 1.0)
  result = cv2.warpAffine(image, rot_mat, image.shape[1::-1], flags=cv2.INTER_LINEAR)
  return result

# Image frame sent to the Flask object
global video_frame
video_frame = None

# Use locks for thread-safe viewing of frames in multiple browsers
global thread_lock 
thread_lock = threading.Lock()

# GStreamer Pipeline to access the Raspberry Pi camera
#GSTREAMER_PIPELINE = 'nvarguscamerasrc ! video/x-raw(memory:NVMM), width=3280, height=2464, format=(string)NV12, framerate=21/1 ! nvvidconv flip-method=0 ! video/x-raw, width=960, height=616, format=(string)BGRx ! videoconvert ! video/x-raw, format=(string)BGR ! appsink wait-on-eos=false max-buffers=1 drop=True'
GSTREAMER_PIPELINE = 'nvarguscamerasrc ! video/x-raw(memory:NVMM), width=1920, height=1080, format=(string)NV12, framerate=21/1 ! nvvidconv flip-method=0 ! video/x-raw, width=960, height=616, format=(string)BGRx ! videoconvert ! video/x-raw, format=(string)BGR ! appsink wait-on-eos=false max-buffers=1 drop=True'

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
    global video_frame, thread_lock, video_capture, trt_yolo, ctx
    # cuda.init()
    # device = cuda.Device(0)  # enter your Gpu id here
    # ctx = device.make_context()
    # ctx.push()
    trt_yolo = TrtYOLO('yolov4-416', 80, None, cuda_ctx=pycuda.autoinit.context)
    video_capture = cv2.VideoCapture(GSTREAMER_PIPELINE, cv2.CAP_GSTREAMER)
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
    fps = 0.0
    tic = time.time()
    cls_dict = get_cls_dict(80)
    if args.verbose:
      print(f'cls_dict={cls_dict}')
    vis = BBoxVisualization(cls_dict)
    while True:
        # Acquire thread_lock to access the global video_frame object
        with thread_lock:
            global video_frame
            if video_frame is None:
                continue
#            return_key, encoded_image = cv2.imencode(".jpg", video_frame)
#            bytes_image = Image.fromarray (np.uint8 (encoded_image))
            #Image.fromarray((encoded_image).astype('uint8'), mode='L').save('pic2.png')
#            print(f'image width={video_capture.get(cv2.CAP_PROP_FRAME_WIDTH)}, image height={video_capture.get(cv2.CAP_PROP_FRAME_HEIGHT)}, image shape={np.uint8(encoded_image).shape}', file=sys.stdout)
            boxes, confs, clss = trt_yolo.detect(video_frame, 0.3)
            if args.verbose:
              if len(boxes) > 0:
                for (cls,box) in zip(clss,boxes):
                  print(f'{cls_dict[cls]}  boxes={box}')
            img = vis.draw_bboxes(video_frame, boxes, confs, clss)
            img = show_fps(img, fps)
            return_key, encoded_image = cv2.imencode(".jpg", img)
            toc = time.time()
            curr_fps = 1.0 / (toc - tic)
            # calculate an exponentially decaying average of fps number
            fps = curr_fps if fps == 0.0 else (fps*0.95 + curr_fps*0.05)
            tic = toc

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

@app.route('/register', methods=['GET', 'POST'])
@token_required
def signup_user(current_user):  
   if request.method == 'GET':
      return render_template('register.html')
   else:
#      data = request.get_json()
      name = request.form['username']
      password = request.form['password']

      hashed_password = generate_password_hash(password, method='sha256')

      new_user = Users(public_id=str(uuid.uuid4()), name=name, password=hashed_password, admin=False) 
      db.session.add(new_user)  
      db.session.commit()    

      return jsonify({'message': 'registered successfully'})   

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
    args = parse_args()
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

    
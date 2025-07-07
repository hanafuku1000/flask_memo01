#（１．仮想環境の起動（有効化）しま←：.venv\Scripts\activate　※起動ごとに必要）
#(２．実行は、flask run　もしくは　python ファイル名.py)
#🔁実行は、（ターミナルで）「.\run.ps1」だけでOK。※run.ps1ファイルを作成してあること。これ1発で仮想環境も起動する。
#※ただし、🔁だけの実行でOKなのは、「.flaskenv」が作成されていることが前提

from flask import Flask

from flask import render_template,g ,request, redirect
#🌸render_template： Flask のテンプレートエンジン「Jinja2」を使って、HTMLファイル（テンプレート）を動的に生成する関数
#↑base.html(例)が使用できる
#🌸g： Flask が提供する「リクエストごとの一時保存スペース」
#→各リクエストごとに状態を保持するグローバル変数のようなもの

import sqlite3 #execute(SQL文を実行),connect(DB接続),cursor(クエリを実行するためのオブジェクトを作成)等

from flask_login import (
    UserMixin #ユーザの情報をオブジェクトとして管理するためのライブラリ 
    ,LoginManager
    ,login_required #ログインしているユーザーだけがこのルートにアクセスできるようにするための関数
    ,login_user
    ,logout_user)

import os

#ハッシュ値の生成、ハッシュ値での認証チェック
from werkzeug.security import generate_password_hash, check_password_hash

#以下よりプログラム本体

#DBの設定
DATABASE = "flaskmemo.db"


#====================================
#ルーティングの設定
#ルーティングとは…：
#====================================

#Flaskクラスのインスタンスを作成
app = Flask(__name__) #__name__：現在のファイル名を指す特別な変数で、Flask がアプリの所在を判断するために使う

app.secret_key = os.urandom(24) #24バイトの秘密鍵をランダムに生成して設定する
#開発中は os.urandom(24) のような “毎回変わるキー” でOKですが、本番環境では固定の秘密鍵を環境変数などで管理


#ログインマネージャーを作成
#ログインマネージャ：現在ログインしているのが誰なのか管理する
login_manager = LoginManager() #ログインの管理機能を準備
login_manager.init_app(app) #Flaskアプリ (＝変数app) に、上で作成した login_managerを接続
#.init_app(app)：FlaskとLoginManagerをリンクさせる


#クラスを作成する（User）
#ログインの状態をユーザで管理するためクラスを作成
class User(UserMixin): #usermixin：Flask-Loginで必要な属性・機能を提供
    def __init__(self,userid):
        self.id = userid #ユーザーの実体（ID保持）

#====================================
#ログインしてるセッションの確認
#====================================
@login_manager.user_loader
def load_user(userid):
    return User(userid)

#unauthorized() 関数を LoginManager の unauthorized_handler() に登録する
@login_manager.unauthorized_handler
def unauthorized():
     return redirect("/login")



#====================================
#ログアウト画面のルーティングの作成
#====================================
@app.route("/logout", methods =["GET"])
def logout():
    logout_user() #ユーザーのログイン状態を解除する(Flask-Login が提供)

    return redirect("/login")

#====================================
#新規登録（サインアップ）画面のルーティングの作成
#====================================
@app.route("/signup", methods = ["GET","POST"])
def signup():
    error_message = ""

    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")
        
        # ① 空欄チェックを最初に！
        if not userid or not password:
            error_message = "ユーザーIDとパスワードを入力してください"
        else:
            pass_hash = generate_password_hash(password, method = "pbkdf2:sha256") #パスワードのハッシュ化
            db= get_db() #DBの接続（ない場合は作成）
            
            try:
                db.execute(
                    "insert into users(userid, password) values(?,?)",
                    [userid, pass_hash] #value(?,?)に代入する値。valueに直接書込むと、変数名ではなく列名として認識されてしまう
                )
                db.commit()
                return redirect("/login")

            except sqlite3.IntegrityError: #データベースの「整合性（integrity）」が壊れるような操作をしようとしたときに出るエラー
                error_message = f"ユーザID【{userid}】はすでに使われています"

            #try-exceptを使わずにuseridのダブりをチェックする方法
            #userid_check = get_db.execute("select userid from users where userid = ?",[userid,]).fetchall()
            #if not userid_check:
                #    ・・・
            #else
                #error_message = f"ユーザID【{userid}】はすでに使われています"


    return render_template("signup.html", error_message = error_message)




#====================================
#ログイン画面のルーティングの作成
#====================================
@app.route("/login", methods = ["GET","POST"]) #ルート関数。呼び出されるタイミングは、指定のURLへリクエストが来た時

def login():
    error_message = "" #引き渡す情報
    userid = ""

    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")

        #ログインのチェック(1):ユーザ登録されたDBと接続し、
        #テーブルから入力されたユーザIDと合致するデータを探し、その"passpord"のみの情報をリスト型で取得
        user_data = get_db().execute(
            "select password from users where userid = ?",[userid,] #パスワードだけ抜き取る
        ).fetchone()

        #ログインのチェック(2):入力されたpasswordからハッシュ値を作成し、登録されているハッシュ値(password列)と合致するか確認
        if user_data is not None: #useridの合致するデータがあった場合は、以下の処理を行う。
            if check_password_hash(user_data[0], password): #user_data[0]と入力されたpasspordをチェックする

                #User クラス（Flask-Loginで定義）のインスタンスを作成
                #userid を使って「ログイン中のユーザー」のオブジェクトを作っています
                user = User(userid) 

                login_user(user) #Flask-Login の関数で、ユーザーをログイン状態にする
                return redirect("/")
            
        error_message="入力されたIDもしくはパスワードが違います"
         



    #ページの呼び出し（移動）する。上記で用意した情報を引き渡す
    return render_template("login.html", userid=userid,error_message=error_message)


#====================================
#TOP画面のルーティング
#====================================

#route()デコレータ:関数のトリガーになるURLをFlaskにつたえる ※←このURLにリクエストが来たら実行
@app.route("/") #← このURLにアクセスが来たら
@login_required #ログインされてないと見られたくないページにつける
def top(): #← この関数を実行して
    #htmlを保存するフォルダ名はtemplatesで固定
    #sqlite3由来のexecute(SQL文を実行),connect(DB接続),cursor(クエリ実行)等
    #fetchall():データ全て取得。他にfetchone():最初の1行だけ（id等で指定）取得、fetchmany(数字)：指定個数取得
    memo_lists = get_db().execute("select id,title,body from memo").fetchall()
    return render_template("index.html", memo_lists=memo_lists) #直接文字を返すのではなく、今回は別途作成したhtmlページを返す
   

#＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝
#新規登録画面（rejist.html)のルーティング
#＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝
#GET：フォームを表示、POST：フォームを送信してデータ処理
#methods：flaskで決められている引数（キー）。自由に変えられる変数名ではない。
@app.route("/regist", methods = ["GET","POST"] )  #← このURLにアクセスが来たら
@login_required #ログインされてないと見られたくないページにつける
def regist(): #← この関数を実行して
    if request.method == "POST":
        #regist.htmlからの情報の取得
        title = request.form.get("title")
        body = request.form.get("body")
        db = get_db() #get_db関数をコール。DBを無ければ作成し、接続する
        db.execute("insert into memo (title, body) values(?,?)",[title,body])
        db.commit() #DBへ書き込み完了
        return redirect("/") #画面を自動で別ページに遷移させる＝"/regist"のルーティングが終了する＝以下の処理は（POSTのときには）行われない


    return render_template("regist.html") 


#====================================
#編集画面（{memo_list.id}/edit.html)のルーティング
#====================================
@app.route("/<id>/edit", methods = ["GET","POST"])
#<×××>：可変のURLを設定できる
@login_required #ログインされてないと見られたくないページにつける
def edit(id):
    #get_db(自作関数)：DBと接続（DBがない場合は作成）
    #execute：SQLの実行⇒execute("SQL文"(,引数（←SQL文にプレースホルダ（=?）が含まれている場合)))
    #Python の sqlite3 モジュール）の仕様として
    #プレースホルダ (=?) に渡す値は「タプル」や「リスト」といった入れ物（シーケンス）で渡す必要がある
    #⇒ id = ?,(id)だと変数idの値そのものを渡そうとしてしまうため、タプルかリストにする必要がある
    #⇒（id,)とするとタプル型になる

    if request.method == "POST":
        #regist.htmlからの情報の取得
        title = request.form.get("title")
        body = request.form.get("body")
        db = get_db() #get_db関数をコール。DBを無ければ作成し、接続する
        db.execute("update memo set title=?, body=? where id = ?",[title,body,id])
        db.commit() #DBへ書き込み完了
        return redirect("/") #画面を自動で別ページに遷移させる＝"/<id</edit"のルーティングが終了する＝以下の処理は（POSTのときには）行われない


    post = get_db().execute("select id,title, body from memo where id = ?",(id,)).fetchone()
    
    #post＝条件に合致（指定したid）し選択された1行分のデータ
    #変数post:row_factoryが設定されていれば、sqlite.Row型、設定されていない場合はタプル型となる（この場合は列名は指定できず、列番号を使ってアクセスすることになる）

    return render_template("edit.html", post = post)


#====================================
#削除画面（{memo_list.id}/delete.html)のルーティング
#====================================
@app.route("/<id>/delete", methods=["POST"]) #.route("/<id>/delete"…)は、表示するサイトアドレス的意味でのURLを結び付けているのではなく、POST（今回の場合は、POSTのみ）の宛先を結び付けている
@login_required #ログインされてないと見られたくないページにつける
def delete(id): #POST（今回の場合は、POSTのみ）でリクエストが送られれば、表示しているサイトページは変わらなくても下記の関数は実行されます
    #index.htmlだけで完了させる。
    # 確認ダイアログはJavaScriptで⇒tkinter使えばいいのかと思ったら、Flask起動中にtkinterを呼び出すことは特殊ケースらしいので避ける
    db = get_db()
    db.execute("DELETE FROM memo WHERE id = ?", (id,))
    db.commit()
    return redirect("/")




#====================================
#メインプログラム
#====================================



if __name__ == "__main__":
    app.run() #app.pyの実行



def connect_db():
    #flaskのconnect(コネクション)オブジェクトには、cursorを自動で内部で作成するようになっている
    rv = sqlite3.connect(DATABASE) #DBを接続する。開発中、ターミナルで「sqlite3 DB名.db」として実行していた部分
    rv.row_factory = sqlite3.Row #列名の取得。通常index番号でしかアクセスできないところ、列名でアクセスできるように出来る
    return rv

def get_db():

    #hasattr：print()と同じく、組込関数
    if not hasattr(g,'sqlite_db'): #gが”sqlite_db”という変数と結び付けられていないならば→ｇは一時的な保存スペース。●現時点で、g.sqlite_dbが定義されていないならば、という意味のif文
        g.sqlite_db = connect_db() #g.sqlite_db：ｇにsqltite_db変数を結び付ける＝格納する。
    return g.sqlite_db


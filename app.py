from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, join_room, emit
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import secrets
from datetime import datetime
import pytz  # <-- NEW

# Timezones
UTC = pytz.utc
IST = pytz.timezone('Asia/Kolkata')  # IST timezone [web:2][web:42][web:46]

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    manage_session=False
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ----------------- MODELS -----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref='owned_rooms')


class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    room = db.relationship('Room', backref='memberships')
    user = db.relationship('User', backref='room_memberships')


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # store in UTC
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))


class ConversationMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    conversation = db.relationship('Conversation', backref='members')
    user = db.relationship('User', backref='conversations_link')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    # store timestamps in UTC (aware)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    edited_at = db.Column(db.DateTime, nullable=True)
    seen_by_receiver = db.Column(db.Boolean, default=False)
    seen_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=True)

    user = db.relationship('User', backref='messages')
    room = db.relationship('Room', backref='messages')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()
    # no default room; users create invite-only groups


# ----------------- HELPERS -----------------

def get_or_create_conversation(user1_id, user2_id):
    convs = (Conversation.query
             .join(ConversationMember)
             .filter(ConversationMember.user_id.in_([user1_id, user2_id]))
             .all())
    for c in convs:
        member_ids = [m.user_id for m in c.members]
        if set(member_ids) == {user1_id, user2_id}:
            return c

    conv = Conversation()
    db.session.add(conv)
    db.session.flush()
    db.session.add(ConversationMember(conversation_id=conv.id, user_id=user1_id))
    db.session.add(ConversationMember(conversation_id=conv.id, user_id=user2_id))
    db.session.commit()
    return conv


def is_room_member(room_id, user_id):
    return RoomMember.query.filter_by(room_id=room_id, user_id=user_id).first() is not None


# ----------------- ROUTES -----------------

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('rooms'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('rooms'))
        flash('Invalid username or password.')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required.')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists.')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if name:
            existing = Room.query.filter_by(name=name).first()
            if existing is None:
                new_room = Room(name=name, owner=current_user)
                db.session.add(new_room)
                db.session.flush()
                # creator is automatically a member
                db.session.add(RoomMember(room_id=new_room.id, user_id=current_user.id))
                db.session.commit()
        return redirect(url_for('rooms'))

    my_room_ids = [m.room_id for m in current_user.room_memberships]
    all_rooms = Room.query.filter(Room.id.in_(my_room_ids)).order_by(Room.name).all()
    return render_template('rooms.html', rooms=all_rooms)


@app.route('/room/<int:room_id>')
@login_required
def room(room_id):
    room_obj = Room.query.get_or_404(room_id)

    if not is_room_member(room_id, current_user.id):
        flash('You are not a member of this group.')
        return redirect(url_for('rooms'))

    messages = (Message.query
                .filter_by(room_id=room_id)
                .order_by(Message.timestamp)
                .all())
    return render_template('room.html', room=room_obj, messages=messages)


@app.route('/room/<int:room_id>/invite', methods=['POST'])
@login_required
def invite_to_room(room_id):
    room_obj = Room.query.get_or_404(room_id)

    if room_obj.owner_id != current_user.id:
        flash('Only the group owner can invite users.')
        return redirect(url_for('room', room_id=room_id))

    username = request.form.get('username', '').strip()
    if not username:
        return redirect(url_for('room', room_id=room_id))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('room', room_id=room_id))

    if not is_room_member(room_id, user.id):
        db.session.add(RoomMember(room_id=room_id, user_id=user.id))
        db.session.commit()
        flash(f'Invited {user.username} to the group.')

    return redirect(url_for('room', room_id=room_id))


@app.route('/users')
@login_required
def users():
    all_users = User.query.filter(User.id != current_user.id).all()
    return render_template('users.html', users=all_users)


@app.route('/private/<int:user_id>')
@login_required
def private_chat(user_id):
    other = User.query.get_or_404(user_id)
    conv = get_or_create_conversation(current_user.id, other.id)
    messages = (Message.query
                .filter_by(conversation_id=conv.id)
                .order_by(Message.timestamp)
                .all())
    return render_template('private.html',
                           conversation=conv,
                           other=other,
                           messages=messages)


# ----------------- SOCKET.IO -----------------

online_users = {}


@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = {
            'sid': request.sid,
            'username': current_user.username
        }
        emit('online_users', list(online_users.values()), broadcast=True)


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.id in online_users:
        del online_users[current_user.id]
        emit('online_users', list(online_users.values()), broadcast=True)


@socketio.on('join_room')
def handle_join_room(data):
    room_id = data['room_id']
    room_obj = Room.query.get(room_id)
    if not room_obj:
        return

    if not is_room_member(room_id, current_user.id):
        return

    join_room(f'room_{room_id}')
    emit('status',
         {'msg': f'{current_user.username} joined {room_obj.name}'},
         room=f'room_{room_id}')


@socketio.on('send_message')
def handle_message(data):
    room_id = data['room_id']
    content = data['content'].strip()
    if not content:
        return

    room_obj = Room.query.get(room_id)
    if not room_obj:
        return

    if not is_room_member(room_id, current_user.id):
        return

    # timestamp stored in UTC by default via model
    message = Message(content=content, user=current_user, room_id=room_id)
    db.session.add(message)
    db.session.commit()

    # Convert to IST for display
    ts_ist = message.timestamp.replace(tzinfo=UTC).astimezone(IST)  # [web:2][web:42][web:46]

    payload_self = {
        'id': message.id,
        'username': current_user.username,
        'content': content,
        'timestamp': ts_ist.strftime('%H:%M'),
        'is_self': True,
        'edited': False
    }
    payload_others = {
        **payload_self,
        'is_self': False
    }

    emit('message', payload_self, room=request.sid)
    emit('message', payload_others, room=f'room_{room_id}', include_self=False)


@socketio.on('join_conversation')
def handle_join_conversation(data):
    conv_id = data['conversation_id']
    join_room(f'conv_{conv_id}')
    emit('status',
         {'msg': f'{current_user.username} opened private chat'},
         room=f'conv_{conv_id}')


@socketio.on('send_private')
def handle_send_private(data):
    conv_id = data['conversation_id']
    content = data['content'].strip()
    if not content:
        return

    conv = Conversation.query.get(conv_id)
    if not conv:
        return

    member_ids = [m.user_id for m in conv.members]
    if current_user.id not in member_ids:
        return

    msg = Message(content=content,
                  user=current_user,
                  conversation_id=conv_id)
    db.session.add(msg)
    db.session.commit()

    ts_ist = msg.timestamp.replace(tzinfo=UTC).astimezone(IST)  # [web:2][web:42][web:46]

    payload_self = {
        'id': msg.id,
        'username': current_user.username,
        'content': content,
        'timestamp': ts_ist.strftime('%H:%M'),
        'is_self': True,
        'edited': False,
        'seen_by_receiver': msg.seen_by_receiver
    }
    payload_other = {
        **payload_self,
        'is_self': False
    }

    emit('private_message', payload_self, room=request.sid)
    emit('private_message', payload_other,
         room=f'conv_{conv_id}', include_self=False)


@socketio.on('delete_message')
def handle_delete_message(data):
    msg_id = data['message_id']
    msg = Message.query.get(msg_id)
    if not msg:
        return
    if msg.user_id != current_user.id:
        return

    db.session.delete(msg)
    db.session.commit()

    emit('message_deleted', {'message_id': msg_id}, broadcast=True)


@socketio.on('edit_message')
def handle_edit_message(data):
    msg_id = data['message_id']
    new_text = data['content'].strip()
    if not new_text:
        return

    msg = Message.query.get(msg_id)
    if not msg:
        return
    if msg.user_id != current_user.id:
        return

    # store edit time in UTC
    msg.content = new_text
    msg.edited_at = datetime.now(UTC)
    db.session.commit()

    edited_ist = msg.edited_at.astimezone(IST)  # [web:2][web:42][web:46]

    emit('message_edited', {
        'message_id': msg.id,
        'content': msg.content,
        'edited_at': edited_ist.strftime('%H:%M')
    }, broadcast=True)


@socketio.on('typing')
def handle_typing(data):
    payload = {
        'username': current_user.username
    }
    room_id = data.get('room_id')
    conv_id = data.get('conversation_id')

    if room_id:
        if not is_room_member(room_id, current_user.id):
            return
        emit('typing', payload, room=f'room_{room_id}', include_self=False)
    elif conv_id:
        emit('typing', payload, room=f'conv_{conv_id}', include_self=False)


@socketio.on('mark_seen')
def handle_mark_seen(data):
    conv_id = data.get('conversation_id')
    if not conv_id:
        return

    conv = Conversation.query.get(conv_id)
    if not conv:
        return

    msgs = (Message.query
            .filter_by(conversation_id=conv_id, seen_by_receiver=False)
            .filter(Message.user_id != current_user.id)
            .all())

    # store seen time in UTC
    now_utc = datetime.now(UTC)
    for m in msgs:
        m.seen_by_receiver = True
        m.seen_at = now_utc
    db.session.commit()

    emit('messages_seen', {
        'conversation_id': conv_id
    }, room=f'conv_{conv_id}')


if __name__ == "__main__":
    app.run()

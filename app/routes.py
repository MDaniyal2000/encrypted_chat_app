import os, json
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm
from app.models import Conversation, Message, User
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user, logout_user, current_user, login_required
from app.implementation import generate_p_and_q, generate_key_pair, encrypt, decrypt

@app.template_filter()
def get_correct_username(conv_id):
    conv = Conversation.query.get(conv_id)
    current_user_id = current_user.user_id
    if conv.user1_id != current_user_id:
        user = User.query.get(conv.user1_id)
        if user:
            return user.username
        else:
            return None
    else:
        user = User.query.get(conv.user2_id)
        if user:
            return user.username
        else:
            return None

@app.template_filter()
def pretty_date(dt):
    return dt.strftime('%d/%m/%Y %H:%M')

@app.template_filter()
def get_plain_text(cipher_text):
    private_key = (current_user.d_value, current_user.n_value)
    return decrypt(private_key, cipher_text)

#Index
@app.route('/')
def index():
    if current_user.is_authenticated:
        user_id = current_user.user_id
        conversations = Conversation.query.filter(
                (Conversation.user1_id == user_id) | (Conversation.user2_id == user_id)
            ).order_by(Conversation.last_updated.desc()).all()
        return redirect(url_for('new_conversation'))
    else:
        return redirect(url_for('login'))

#Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        trials = 0
        p = None
        q = None
        while True:
            if trials >= 5:
                flash('Registration failed, try again later', 'danger')
                return redirect(url_for('register'))
            p, q = generate_p_and_q()
            user_exists = User.query.filter_by(p_value=p, q_value=q).first()
            if user_exists:
                trials += 1
            else:
                break
            
        e, d, n = generate_key_pair(p, q)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, p_value=p, q_value=q, e_value=e, d_value=d, n_value=n)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', active_route='register', form=form)

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash('Username does not exist', 'danger')
        else:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials, please enter correct username and password', 'danger')
    return render_template('login.html', active_route='login', form=form)

#Logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

#New Conversation
@app.route('/new_conversation')
@login_required
def new_conversation():
    user_id = current_user.user_id
    conversations = Conversation.query.filter(
            (Conversation.user1_id == user_id) | (Conversation.user2_id == user_id)
        ).order_by(Conversation.last_updated.desc()).all()
    ids_excluded = [conversation.user2_id for conversation in Conversation.query.filter_by(user1_id=user_id).all()]
    ids_excluded += [conversation.user1_id for conversation in Conversation.query.filter_by(user2_id=user_id).all()]
    ids_excluded += [user_id]
    new_users = User.query.filter(User.user_id.notin_(ids_excluded)).all()
    return render_template('new_conversation.html', conversations=conversations, active_route='new_conversation', new_users=new_users)

#Start Conversation
@app.route('/start_conversation', methods=['POST'])
@login_required
def start_conversation():
    receiver_id = request.form['user_id']
    receiver_user = User.query.get(receiver_id)
    sender_id = current_user.user_id
    conversation = Conversation(user1_id=sender_id, user2_id=receiver_id)
    db.session.add(conversation)
    db.session.commit()

    #Add a message
    plain_text = 'Hi'

    sender_pk = (current_user.e_value, current_user.n_value)
    receiver_pk = (receiver_user.e_value, receiver_user.n_value)

    cipher_sender_copy = encrypt(sender_pk, plain_text)
    cipher_receiver_copy = encrypt(receiver_pk, plain_text)
    message = Message(sender_id=sender_id, receiver_id=receiver_id, sender_copy=cipher_sender_copy, receiver_copy=cipher_receiver_copy, of_conversation=conversation)
    db.session.add(message)
    db.session.commit()

    #Update conversation updated datetime
    conversation.last_updated = message.sent_dt
    db.session.commit()

    #Redirect to the newly started conversation
    return redirect(url_for('show_conversation', conversation_id=conversation.conversation_id))

#Show Conversation
@app.route('/show_conversation/<int:conversation_id>', methods=['GET'])
@login_required
def show_conversation(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if not conversation:
        flash('Conversation does not exist', 'danger')
        return redirect(url_for('index'))

    #Check if logged in user is eligible to view this conversation
    user_id = current_user.user_id
    if user_id not in [conversation.user1_id, conversation.user2_id]:
        flash('You are not authorized to view this conversation', 'danger')
        return redirect(url_for('index'))

    messages = conversation.messages.all()
    conversations = Conversation.query.filter(
            (Conversation.user1_id == user_id) | (Conversation.user2_id == user_id)
        ).order_by(Conversation.last_updated.desc()).all()

    return render_template('conversation.html', conversations=conversations, active_conversation=conversation.conversation_id, messages=messages)
        
#Post Message
@app.route('/post_message', methods=['POST'])
@login_required
def post_message():
    user_id = current_user.user_id
    conversation_id = request.form['active_conversation']
    conversation = Conversation.query.get(conversation_id)
    message_content = request.form['content']
    pic = request.files.get('image')

    sender_id = current_user.user_id
    receiver_id = None
    conversation_user1 = conversation.user1_id
    conversation_user2 = conversation.user2_id
    if sender_id == conversation_user1:
        receiver_id = conversation_user2
    else:
        receiver_id = conversation_user1

    sender_user = User.query.get(sender_id)
    receiver_user = User.query.get(receiver_id)

    sender_pk = (sender_user.e_value, sender_user.n_value)
    receiver_pk = (receiver_user.e_value, receiver_user.n_value)
    
    if pic:
        filename = pic.filename
        if '.' not in filename:
            flash('File extension not allowed', 'danger')
            return redirect(url_for('show_conversation', conversation_id=conversation_id))

        ext = filename.rsplit(".", 1)[1]
        if ext.upper() not in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
            flash('File extension not allowed', 'danger')
            return redirect(url_for('show_conversation', conversation_id=conversation_id))

        image_name = f'{user_id}-{filename}' 

        cipher_sender_copy = encrypt(sender_pk, image_name)
        cipher_receiver_copy = encrypt(receiver_pk, image_name)

        #Insert image
        message = Message(sender_id=sender_id, receiver_id=receiver_id, sender_copy=cipher_sender_copy, receiver_copy=cipher_receiver_copy, of_conversation=conversation, is_image=True)
        db.session.add(message)
        db.session.commit()

        path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        pic.save(path)

        #Update conversation updated datetime
        conversation.last_updated = message.sent_dt
        db.session.commit()

        if message_content:
            cipher_sender_copy = encrypt(sender_pk, message_content)
            cipher_receiver_copy = encrypt(receiver_pk, message_content)

            message = Message(sender_id=sender_id, receiver_id=receiver_id, sender_copy=cipher_sender_copy, receiver_copy=cipher_receiver_copy, of_conversation=conversation)
            db.session.add(message)
            db.session.commit()

            #Update conversation updated datetime
            conversation.last_updated = message.sent_dt
            db.session.commit()
    else:
        if not message_content:
            flash('Message can not be empty', 'danger')
        else:
            cipher_sender_copy = encrypt(sender_pk, message_content)
            cipher_receiver_copy = encrypt(receiver_pk, message_content)

            message = Message(sender_id=sender_id, receiver_id=receiver_id, sender_copy=cipher_sender_copy, receiver_copy=cipher_receiver_copy, of_conversation=conversation)
            db.session.add(message)
            db.session.commit()

            #Update conversation updated datetime
            conversation.last_updated = message.sent_dt
            db.session.commit()

    return redirect(url_for('show_conversation', conversation_id=conversation_id))

@app.route('/get_messages_count', methods=['POST'])
@login_required
def get_messages_count():
    conversation_id = request.get_data(as_text=True)
    conversation = Conversation.query.get(conversation_id)
    if not conversation:
        return json.dumps({
        'count' : 0
    })
    else:
        return json.dumps({
        'count' : conversation.messages.count()
    })

@app.route('/get_messages', methods=['POST'])
@login_required
def get_messages():
    conversation_id = request.get_data(as_text=True)
    conversation = Conversation.query.get(conversation_id)
    messages = conversation.messages.all()
    return render_template('messages.html', active_conversation=conversation_id, messages=messages)

@app.route('/regenerate_keys')
@login_required
def regenerate_keys():
    trials = 0
    p = None
    q = None
    while True:
        if trials >= 5:
            flash('Failed to generate new keys, try again later', 'danger')
            return redirect(url_for('index'))
        p, q = generate_p_and_q()
        user_exists = User.query.filter_by(p_value=p, q_value=q).first()
        if user_exists:
            trials += 1
        else:
            break
        
    e, d, n = generate_key_pair(p, q)
    current_user.p_value = p
    current_user.q_value = q
    current_user.e_value = e
    current_user.d_value = d
    current_user.n_value = n
    db.session.commit()
    flash('Your keys have been updated', 'success')
    return redirect(request.referrer)
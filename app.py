import os, json, uuid, bleach, logging
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, session
from config import Config
from extensions import db, login_manager, socketio, limiter
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    limiter.init_app(app)
    
    # Set up logging (rotate error logs)
    if not app.debug:
        file_handler = logging.handlers.RotatingFileHandler('ticketing_error.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.ERROR)
        app.logger.addHandler(file_handler)
    
    # Ensure uploads folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    from models import User, Ticket, Message, Log

    # Inject current_user into templates using a context processor
    @app.context_processor
    def inject_current_user():
        return {'current_user': getattr(request, 'current_user', None)}
    
    # --- Authentication Routes ---
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if session.get('user_id'):
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            if User.query.filter_by(email=email).first():
                flash('Email already registered.')
                return redirect(url_for('register'))
            user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            if not safe_commit(db, app):
                return redirect(url_for('register'))
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
        return render_template('register.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        if session.get('user_id'):
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                session.clear()
                session['user_id'] = user.id
                flash('Logged in successfully.')
                return redirect(url_for('dashboard'))
            flash('Invalid email or password.')
        return render_template('login.html')
    
    @app.before_request
    def load_logged_in_user():
        user_id = session.get('user_id')
        if user_id is None:
            setattr(request, 'current_user', None)
        else:
            setattr(request, 'current_user', User.query.get(user_id))
    
    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out.')
        return redirect(url_for('login'))
    
    # --- Dashboard and Ticket Routes ---
    @app.route('/')
    def dashboard():
        current_user = getattr(request, 'current_user', None)
        if not current_user:
            return redirect(url_for('login'))
        tickets = Ticket.query.all() if current_user.role == 'Admin' else Ticket.query.filter_by(creator_id=current_user.id).all()
        return render_template('dashboard.html', tickets=tickets)
    
    @app.route('/ticket/create', methods=['GET', 'POST'])
    def ticket_create():
        current_user = getattr(request, 'current_user', None)
        if not current_user:
            return redirect(url_for('login'))
        if request.method == 'POST':
            title = request.form['title']
            description_raw = request.form['description']
            # Allowed HTML tags for the rich text editor
            allowed_tags = ['p', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br']
            description = bleach.clean(description_raw, tags=allowed_tags, strip=True)
            priority = request.form.get('priority', 'normal')
            tags = request.form.get('tags', '')
            try:
                custom_fields = json.loads(request.form.get('custom_fields', '{}'))
            except json.JSONDecodeError:
                flash("Invalid JSON for custom fields.")
                return redirect(url_for('ticket_create'))
            ticket = Ticket(
                title=title,
                description=description,
                priority=priority,
                tags=tags,
                custom_fields=custom_fields,
                creator_id=current_user.id
            )
            db.session.add(ticket)
            if not safe_commit(db, app):
                return redirect(url_for('ticket_create'))
            socketio.emit('new_ticket', {'ticket_id': ticket.id, 'title': ticket.title}, broadcast=True)
            flash('Ticket created successfully.')
            return redirect(url_for('dashboard'))
        return render_template('ticket_create.html')
    
    @app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
    def ticket_detail(ticket_id):
        current_user = getattr(request, 'current_user', None)
        if not current_user:
            return redirect(url_for('login'))
        ticket = Ticket.query.get_or_404(ticket_id)
        if request.method == 'POST':
            content_raw = request.form['content']
            content = bleach.clean(content_raw, tags=[], strip=True)
            file = request.files.get('attachment')
            filename = None
            if file and file.filename != '' and allowed_file(file.filename, app):
                filename = save_uploaded_file(file, app)
            message = Message(ticket_id=ticket.id, sender_id=current_user.id, content=content, attachment=filename)
            db.session.add(message)
            if not safe_commit(db, app):
                return redirect(url_for('ticket_detail', ticket_id=ticket.id))
            socketio.emit('ticket_update', {'ticket_id': ticket.id}, room=f'ticket_{ticket.id}')
            flash('Response added.')
            return redirect(url_for('ticket_detail', ticket_id=ticket.id))
        messages = Message.query.filter_by(ticket_id=ticket.id).order_by(Message.created_at).all()
        return render_template('ticket_detail.html', ticket=ticket, messages=messages)
    
    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    @app.route('/chat/<int:ticket_id>')
    def chat(ticket_id):
        current_user = getattr(request, 'current_user', None)
        if not current_user:
            return redirect(url_for('login'))
        ticket = Ticket.query.get_or_404(ticket_id)
        messages = Message.query.filter_by(ticket_id=ticket.id).order_by(Message.created_at).all()
        return render_template('chat.html', ticket=ticket, messages=messages)
    
    @app.route('/admin/tickets', methods=['GET'])
    def admin_tickets():
        current_user = getattr(request, 'current_user', None)
        if not current_user or current_user.role != 'Admin':
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        tickets = Ticket.query.all()
        return render_template('admin/tickets.html', tickets=tickets)
    
    @app.route('/admin/ticket/<int:ticket_id>/edit', methods=['GET', 'POST'])
    def admin_ticket_edit(ticket_id):
        current_user = getattr(request, 'current_user', None)
        if not current_user or current_user.role != 'Admin':
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        ticket = Ticket.query.get_or_404(ticket_id)
        if request.method == 'POST':
            ticket.status = request.form.get('status', ticket.status)
            ticket.priority = request.form.get('priority', ticket.priority)
            agent_id = request.form.get('assigned_to_id')
            if agent_id:
                ticket.assigned_to_id = int(agent_id)
            if not safe_commit(db, app):
                return redirect(url_for('admin_ticket_edit', ticket_id=ticket.id))
            flash('Ticket updated.')
            return redirect(url_for('admin_tickets'))
        from models import User
        agents = User.query.filter(User.role=='Support').all()
        return render_template('admin/ticket_edit.html', ticket=ticket, agents=agents)
    
    # --- WebSocket Handlers ---
    @socketio.on('join')
    def on_join(data):
        try:
            ticket_id = data.get('ticket_id')
            from models import Ticket
            ticket = Ticket.query.get(ticket_id)
            current_user = getattr(request, 'current_user', None)
            if not ticket or (ticket.creator_id != current_user.id and 
                              ticket.assigned_to_id != current_user.id and 
                              current_user.role != 'Admin'):
                emit('error', {'msg': 'Unauthorized access to this ticket room.'})
                return
            room = f'ticket_{ticket_id}'
            join_room(room)
            emit('status', {'msg': f'{current_user.username} has joined the chat.'}, room=room)
        except Exception as e:
            app.logger.error(f"Join error: {e}")
    
    @socketio.on('leave')
    def on_leave(data):
        try:
            ticket_id = data.get('ticket_id')
            room = f'ticket_{ticket_id}'
            leave_room(room)
            current_user = getattr(request, 'current_user', None)
            emit('status', {'msg': f'{current_user.username} has left the chat.'}, room=room)
        except Exception as e:
            app.logger.error(f"Leave error: {e}")
    
    @socketio.on('message')
    def handle_message(data):
        try:
            ticket_id = data.get('ticket_id')
            content_raw = data.get('content')
            content = bleach.clean(content_raw, tags=[], strip=True)
            current_user = getattr(request, 'current_user', None)
            message = Message(ticket_id=ticket_id, sender_id=current_user.id, content=content)
            db.session.add(message)
            safe_commit(db, app)
            room = f'ticket_{ticket_id}'
            emit('message', {'sender': current_user.username, 'content': content, 'timestamp': datetime.utcnow().isoformat()}, room=room)
        except Exception as e:
            app.logger.error(f"WebSocket message handling error: {e}")
            emit('error', {'msg': 'Error processing your message.'})
    
    # --- Export and Logs ---
    @app.route('/export/tickets/csv')
    def export_tickets_csv():
        current_user = getattr(request, 'current_user', None)
        if not current_user or current_user.role != 'Admin':
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        import pandas as pd
        tickets = Ticket.query.all()
        data = []
        for t in tickets:
            data.append({
                'Title': t.title,
                'Creation Date': t.created_at,
                'Creator': t.creator.username,
                'Status': t.status
            })
        df = pd.DataFrame(data)
        csv_data = df.to_csv(index=False)
        return csv_data, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=tickets.csv'}
    
    @app.route('/admin/logs/<log_type>')
    def view_logs(log_type):
        current_user = getattr(request, 'current_user', None)
        if not current_user or current_user.role != 'Admin':
            flash('Access denied.')
            return redirect(url_for('dashboard'))
        logs = Log.query.filter_by(log_type=log_type).order_by(Log.timestamp.desc()).all()
        return render_template('admin/logs.html', logs=logs, log_type=log_type)
    
    # --- Error Handlers ---
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error('Server Error: %s', error)
        return render_template('500.html'), 500
    
    return app

# --- Utility Functions ---
def allowed_file(filename, app):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file, app):
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    try:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        return unique_filename
    except Exception as e:
        app.logger.error(f"Failed to save file: {e}")
        flash("File upload failed.")
        return None

def safe_commit(db, app):
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database commit error: {e}")
        flash("An error occurred. Please try again.")
        return False

# Import join_room, leave_room, emit for Socket.IO handlers
from flask_socketio import join_room, leave_room, emit

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)

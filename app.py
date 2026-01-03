import os
import socket
import qrcode
import datetime
import json
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

# Configuration
app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management' # Change in production
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'currency.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database Path Configuration
if 'ANDROID_PRIVATE' in os.environ:
    # On Android, use the private storage to ensure writability
    db_path = os.path.join(os.environ['ANDROID_PRIVATE'], 'currency.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
else:
    # On Desktop, use the local directory
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'currency.db')

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    balance = db.Column(db.Integer, default=100) # Start with 100 credits
    is_admin = db.Column(db.Boolean, default=False)
    is_banker = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(20), default='#3b82f6') # Default blue

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=True) # Null for System/Mint
    receiver = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    note = db.Column(db.String(200))

class SystemSetting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(200))

# --- Helpers ---
def get_setting(key, default=None):
    setting = SystemSetting.query.get(key)
    return setting.value if setting else default

def set_setting(key, value):
    setting = SystemSetting.query.get(key)
    if not setting:
        setting = SystemSetting(key=key, value=value)
        db.session.add(setting)
    else:
        setting.value = value
    db.session.commit()

def init_bank_user():
    bank = User.query.filter_by(username='Bank').first()
    if not bank:
        bank = User(username='Bank', balance=0, color='#1e3a8a', is_banker=True) # Deep Blue for Bank, bank start without money
        db.session.add(bank)
        db.session.commit()
        print("Bank user initialized.")
    return bank

def get_local_ip():
    # Primary: Linux 'hostname -I' (works offline/LAN-only)
    try:
        import subprocess
        output = subprocess.check_output("hostname -I", shell=True).decode('utf-8').strip()
        if output:
            return output.split()[0] # Take the first IP
    except Exception:
        pass

    # Fallback: Socket connection (requires gateway/internet routing)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
        s.close()
    except Exception:
        IP = '127.0.0.1'
    return IP

def format_currency(value):
    if value is None:
        return "$0"
    return "${:,.0f}".format(value)

app.jinja_env.filters['currency'] = format_currency

# --- Routes ---

@app.route('/host_login')
def host_login():
    # Backdoor for the local host device to become admin
    # In a real app, verify this request comes from localhost or has a token
    # For this local game, we assume clicking the button in the app is sufficient auth
    
    # Ensure Host user exists
    host_user = User.query.filter_by(username='Host').first()
    if not host_user:
        host_user = User(username='Host', balance=1000000, is_admin=True, is_banker=True, color='#ffffff')
        db.session.add(host_user)
        db.session.commit()
    
    session['user'] = 'Host'
    session['is_admin'] = True
    flash("Welcome, Game Host!")
    return redirect(url_for('admin_dashboard'))

@app.route('/')
def index():
    # Ensure Bank always exists
    init_bank_user()
    
    if 'user' not in session:
        # Fetch data for Login Chart
        users = User.query.order_by(User.balance.desc()).all()
        active_users = [u for u in users if u.balance > 0]
        chart_labels = [u.username for u in active_users]
        chart_data = [u.balance for u in active_users]
        monopoly_mode = get_setting('monopoly_mode') == '1'
        
        return render_template_string(LOGIN_TEMPLATE, 
                                      request_args=request.args,
                                      chart_labels=json.dumps(chart_labels),
                                      chart_data=json.dumps(chart_data),
                                      monopoly_mode=monopoly_mode)
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        session.pop('user', None)
        return redirect(url_for('index'))

    # Transaction History
    history = Transaction.query.filter(
        (Transaction.sender == current_user.username) | 
        (Transaction.receiver == current_user.username)
    ).order_by(Transaction.timestamp.desc()).limit(20).all()

    # All Users (Pinned Bank + Alphabetical others)
    # Fetch all users excluding current user and Bank
    other_users = User.query.filter(User.username != current_user.username, User.username != 'Bank').order_by(User.username.asc()).all()
    
    recents = []
    bank_user = User.query.filter_by(username='Bank').first()
    if bank_user:
        recents.append(bank_user)
        
    recents.extend(other_users)

    # Pre-fill transfer if query param exists
    send_to = request.args.get('send_to', '')
    
    # Get last tx id for polling
    last_tx = Transaction.query.filter(
        (Transaction.sender == current_user.username) |
        (Transaction.receiver == current_user.username)
    ).order_by(Transaction.id.desc()).first()
    last_tx_id = last_tx.id if last_tx else 0
    
    # Generate My Request QR Code
    # The URL that others scan to pay me
    my_ip = get_local_ip()
    request_url = f"http://{my_ip}:5000/?send_to={current_user.username}"
    
    # Check Monopoly Mode
    monopoly_mode = get_setting('monopoly_mode') == '1'
    
    # Get Free Parking balance
    free_parking = User.query.filter_by(username='Free Parking').first()
    fp_balance = free_parking.balance if free_parking else None

    return render_template_string(DASHBOARD_TEMPLATE, 
                                  user=current_user, 
                                  history=history, 
                                  recents=recents,
                                  send_to=send_to,
                                  request_url=request_url,
                                  initial_tx_id=last_tx_id,
                                  monopoly_mode=monopoly_mode,
                                  free_parking_balance=fp_balance)

@app.route('/leaderboard')
def leaderboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    users = User.query.order_by(User.balance.desc()).all()
    total_circulation = sum(u.balance for u in users)
    
    # Prepare data for Chart.js
    active_users = [u for u in users if u.balance > 0]
    chart_labels = [u.username for u in active_users]
    chart_data = [u.balance for u in active_users]
    
    return render_template_string(LEADERBOARD_TEMPLATE, 
                                  users=users, 
                                  total_circulation=total_circulation,
                                  chart_labels=json.dumps(chart_labels),
                                  chart_data=json.dumps(chart_data))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username').strip()
    if not username:
        flash("Username cannot be empty")
        return redirect(url_for('index'))
        
    if username.lower() == 'bank':
        flash("Cannot login as System Bank")
        return redirect(url_for('index'))
    
    # Check if user exists, if not create
    user = User.query.filter_by(username=username).first()
    if not user:
        start_balance = 1500 if get_setting('monopoly_mode') == '1' else 100
        user = User(username=username, balance=start_balance) # Sign up bonus
        db.session.add(user)
        db.session.commit()
    
    session['user'] = user.username
    
    # Preserve query params for deep linking
    send_to = request.args.get('send_to')
    if send_to:
        return redirect(url_for('index', send_to=send_to))
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    sender = User.query.filter_by(username=session['user']).first()
    recipient_name = request.form.get('recipient')
    try:
        amount = int(float(request.form.get('amount')))
    except ValueError:
        flash("Invalid amount")
        return redirect(url_for('index'))

    if amount <= 0:
        flash("Amount must be positive")
        return redirect(url_for('index'))

    recipient = User.query.filter_by(username=recipient_name).first()
    
    if not recipient:
        flash("Recipient not found")
        return redirect(url_for('index'))
    
    # Handle Banker Source
    source = request.form.get('source')
    real_sender = sender
    
    if sender.is_banker and source in ['bank', 'parking']:
        if source == 'bank':
            real_sender = User.query.filter_by(username='Bank').first()
            if not real_sender:
                flash("Bank account not found. Contact Admin.")
                return redirect(url_for('index'))
        elif source == 'parking':
            real_sender = User.query.filter_by(username='Free Parking').first()
            if not real_sender:
                flash("Free Parking account not initialized")
                return redirect(url_for('index'))
    else:
        # Standard check for self-transfer
        if sender.username == recipient.username:
            flash("Cannot send money to yourself")
            return redirect(url_for('index'))

    if real_sender.balance < amount and real_sender.username != 'Bank': # Bank has infinite overdraft effectively? Or strict? Let's assume strict but Bank starts high.
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "error": "Insufficient funds"}), 400
        flash("Insufficient funds")
        return redirect(url_for('index'))

    # Execute Transaction
    real_sender.balance -= amount
    recipient.balance += amount
    
    tx = Transaction(sender=real_sender.username, receiver=recipient.username, amount=amount, note="Transfer" if real_sender == sender else f"Banker Transfer by {sender.username}")
    db.session.add(tx)
    db.session.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": True, "new_balance": sender.balance}) # Return user's balance even if they sent from bank

    flash(f"Sent {amount} to {recipient.username}")
    return redirect(url_for('index', send_to=recipient_name))

@app.route('/qr_image')
def qr_image():
    if 'user' not in session:
        return "Unauthorized", 403
    
    user = session['user']
    ip = get_local_ip()
    data = f"http://{ip}:5000/?send_to={user}"
    
    import io
    from flask import send_file
    
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.route('/api/users')
def api_users():
    # Simple API for autocomplete
    search = request.args.get('q', '').lower()
    if search:
        users = User.query.filter(User.username.ilike(f'%{search}%')).all()
    else:
        users = User.query.all()
    return jsonify([u.username for u in users])

@app.route('/api/status')
def api_status():
    if 'user' not in session:
        return jsonify({'error': 'logged_out'}), 401
    
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        return jsonify({'error': 'user_not_found'}), 404

    # Get latest transaction ID for this user
    last_tx = Transaction.query.filter(
        (Transaction.sender == user.username) | 
        (Transaction.receiver == user.username)
    ).order_by(Transaction.id.desc()).first()
    
    last_tx_id = last_tx.id if last_tx else 0
    
    # Get Free Parking balance
    free_parking = User.query.filter_by(username='Free Parking').first()
    fp_balance = free_parking.balance if free_parking else None
    
    return jsonify({
        'balance': user.balance,
        'last_tx_id': last_tx_id,
        'free_parking_balance': fp_balance
    })

@app.route('/pass_go', methods=['POST'])
def pass_go():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    if get_setting('monopoly_mode') != '1':
        flash("Monopoly Mode is disabled")
        return redirect(url_for('index'))
    
    user = User.query.filter_by(username=session['user']).first()
    bank = User.query.filter_by(username='Bank').first()
    
    if user and bank:
        amount = 200
        # Bank pays user
        bank.balance -= amount
        user.balance += amount
        db.session.add(Transaction(sender='Bank', receiver=user.username, amount=amount, note="Pass Go Reward"))
        db.session.commit()
        flash(f"Collected {amount} from Bank!")
        
    return redirect(url_for('index'))

@app.route('/admin/toggle_monopoly', methods=['POST'])
def admin_toggle_monopoly():
    if not session.get('is_admin'):
        return redirect(url_for('admin'))
    
    current = get_setting('monopoly_mode')
    new_state = '0' if current == '1' else '1'
    set_setting('monopoly_mode', new_state)
    
    status = "ENABLED" if new_state == '1' else "DISABLED"
    flash(f"Monopoly Mode {status}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_banker', methods=['POST'])
def admin_toggle_banker():
    if not session.get('is_admin'):
        return redirect(url_for('admin'))
    
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if user and user.username != 'Bank':
        user.is_banker = not user.is_banker
        db.session.commit()
        status = "promoted to Banker" if user.is_banker else "demoted from Banker"
        flash(f"{username} {status}")
    
    return redirect(url_for('admin_dashboard'))

# --- Admin Routes ---

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'ADMIN123':
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid Password")
    
    return render_template_string(ADMIN_LOGIN_TEMPLATE)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin'))
    
    users = User.query.all()
    total_circulation = sum(u.balance for u in users)
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(1000).all()

    # Calculate transaction counts per user
    user_stats = []
    for u in users:
        count = Transaction.query.filter((Transaction.sender == u.username) | (Transaction.receiver == u.username)).count()
        user_stats.append({
            'username': u.username,
            'balance': u.balance,
            'tx_count': count,
            'is_banker': u.is_banker
        })
    
    return render_template_string(ADMIN_DASHBOARD_TEMPLATE, 
                                  user_stats=user_stats, 
                                  total_circulation=total_circulation,
                                  transactions=transactions,
                                  all_users=[u.username for u in users],
                                  monopoly_mode=get_setting('monopoly_mode')=='1',
                                  container_class='max-w-[95%] 2xl:max-w-[1800px]',
                                  free_parking_balance=User.query.filter_by(username='Free Parking').first().balance if User.query.filter_by(username='Free Parking').first() else 0)

@app.route('/admin/action', methods=['POST'])
def admin_action():
    if not session.get('is_admin'):
        return redirect(url_for('admin'))
    
    action = request.form.get('action') # Legacy, now we rely on sender/receiver mostly, or we can keep action for reset
    
    if action == 'reset':
         if request.form.get('confirm') == 'yes':
            db.session.query(Transaction).delete()
            db.session.query(User).delete()
            db.session.commit()
            init_bank_user()
            flash("Database Reset Complete (Bank Restored)")
         return redirect(url_for('admin_dashboard'))

    elif action == 'create_free_parking':
        if not User.query.filter_by(username='Free Parking').first():
            fp = User(username='Free Parking', balance=0)
            db.session.add(fp)
            db.session.commit()
            flash("Free Parking account created!")
        else:
            flash("Free Parking account already exists")
        return redirect(url_for('admin_dashboard'))

    elif action == 'delete_user':
        user_to_delete = request.form.get('username')
        if user_to_delete == 'Bank':
            flash("Cannot delete the Central Bank")
        else:
            user = User.query.filter_by(username=user_to_delete).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                flash(f"User '{user_to_delete}' has been permanently deleted")
            else:
                flash(f"User '{user_to_delete}' not found")
        return redirect(url_for('admin_dashboard'))

    sender_name = request.form.get('sender')
    receiver_name = request.form.get('receiver')
    
    try:
        amount = int(float(request.form.get('amount', 0)))
    except:
        amount = 0

    if amount <= 0 and action != 'set': # Set might not use this logic, but let's stick to the new flow
         # If we are doing a generic transfer
         if sender_name != 'SET_BALANCE':
             flash("Amount must be positive")
             return redirect(url_for('admin_dashboard'))

    # Handle Special Cases based on dropdowns
    
    # 1. SET BALANCE Logic (Special Sender flag)
    if sender_name == 'SET_BALANCE':
        target = User.query.filter_by(username=receiver_name).first()
        if target:
            old_balance = target.balance
            diff = amount - old_balance
            if diff != 0:
                target.balance = amount
                if diff > 0:
                    db.session.add(Transaction(sender="ADMIN", receiver=target.username, amount=diff, note="Admin Set Balance"))
                else:
                    db.session.add(Transaction(sender=target.username, receiver="ADMIN", amount=abs(diff), note="Admin Set Balance"))
                db.session.commit()
                flash(f"Set balance for {receiver_name} to {amount}")
        else:
             flash("User not found")
        return redirect(url_for('admin_dashboard'))

    # 2. MINT (Sender = MINT)
    if sender_name == 'MINT':
        target = User.query.filter_by(username=receiver_name).first()
        if target:
            target.balance += amount
            db.session.add(Transaction(sender="MINT", receiver=target.username, amount=amount, note="Admin Mint"))
            db.session.commit()
            flash(f"Minted {amount} for {receiver_name}")
        else:
             flash("User not found")
        return redirect(url_for('admin_dashboard'))

    # 3. BURN (Receiver = BURN)
    if receiver_name == 'BURN':
        target = User.query.filter_by(username=sender_name).first()
        if target:
            target.balance = max(0, target.balance - amount)
            db.session.add(Transaction(sender=target.username, receiver="BURN", amount=amount, note="Admin Burn"))
            db.session.commit()
            flash(f"Burned {amount} from {sender_name}")
        else:
             flash("User not found")
        return redirect(url_for('admin_dashboard'))

    # 4. Standard Transfer (User to User, including Bank)
    sender = User.query.filter_by(username=sender_name).first()
    receiver = User.query.filter_by(username=receiver_name).first()

    if not sender:
        flash(f"Sender {sender_name} not found")
    elif not receiver:
        flash(f"Receiver {receiver_name} not found")
    else:
        # Check balance? As admin, maybe we allow overdrafts? 
        # Requirement: "Transfer money from anywhere to anywhere"
        # Let's enforce balance check generally, but maybe allow Bank to overdraft?
        # User said "from anywhere", implies control. Let's just do it.
        # If we want to strictly follow physics:
        sender.balance -= amount
        receiver.balance += amount
        db.session.add(Transaction(sender=sender.username, receiver=receiver.username, amount=amount, note="Admin Transfer"))
        db.session.commit()
        flash(f"Transferred {amount} from {sender_name} to {receiver_name}")

    return redirect(url_for('admin_dashboard'))

# --- Templates ---

HTML_BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>WireMoney</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; font-family: sans-serif; }
        .card { background-color: #2d3748; padding: 2rem; border-radius: 0.75rem; margin-bottom: 1.5rem; }
        input, select { background-color: #4a5568; border: none; padding: 1rem; border-radius: 0.5rem; width: 100%; color: white; margin-bottom: 0.75rem; font-size: 1.125rem; }
        button { width: 100%; padding: 1rem; border-radius: 0.5rem; font-weight: bold; transition: background 0.2s; font-size: 1.125rem; }
        .btn-primary { background-color: #4299e1; color: white; }
        .btn-primary:hover { background-color: #3182ce; }
        .btn-danger { background-color: #f56565; color: white; }
        .btn-success { background-color: #48bb78; color: white; }
        /* Horizontal scroll for quick contacts */
        .scrolling-wrapper { -webkit-overflow-scrolling: touch; }
        .scrolling-wrapper::-webkit-scrollbar { display: none; }
        /* Table row hover effect */
        .hover-row:hover { background-color: #4a5568; cursor: pointer; }
    </style>
</head>
<body class="p-6 {{ container_class|default('max-w-4xl') }} mx-auto pb-20">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="mb-6 p-4 bg-blue-600 rounded-lg text-center text-lg font-bold shadow-xl">
        {% for message in messages %}
          <div>{{ message }}</div>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    
    {% block content %}{% endblock %}
</body>
</html>
"""

LOGIN_TEMPLATE = HTML_BASE.replace('{% block content %}{% endblock %}', """
<div class="card text-center mt-10 max-w-md mx-auto">
    <h1 class="text-4xl font-bold mb-8 text-blue-400 tracking-tight">WireMoney</h1>
    <p class="mb-6 text-lg text-gray-300">Enter a username to join the economy.</p>
    <form action="{{ url_for('login', **request_args) }}" method="POST">
        <input type="text" name="username" id="usernameInput" placeholder="Username" required autocomplete="off" class="text-center text-2xl h-16 rounded-xl">
        <button type="submit" class="btn-primary mt-6 py-5 text-xl rounded-xl shadow-lg">Join Economy</button>
    </form>
</div>

{% if monopoly_mode %}
<div class="card mt-8 max-w-md mx-auto">
    <h2 class="text-center text-xl font-bold text-gray-400 mb-4 uppercase tracking-widest">Select Player</h2>
    <div class="relative h-64 w-full">
        <canvas id="loginChart"></canvas>
    </div>
    <p class="text-center text-sm text-gray-500 mt-4 italic">Click a slice to pick your character</p>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    const ctx = document.getElementById('loginChart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: {{ chart_labels | safe }},
            datasets: [{
                data: {{ chart_data | safe }},
                backgroundColor: [
                    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', 
                    '#ec4899', '#6366f1', '#14b8a6', '#f97316', '#84cc16'
                ],
                borderWidth: 2,
                borderColor: '#2d3748'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            onClick: (e, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const username = chart.data.labels[index];
                    document.getElementById('usernameInput').value = username;
                }
            }
        }
    });
</script>
{% endif %}
""")

DASHBOARD_TEMPLATE = HTML_BASE.replace('{% block content %}{% endblock %}', """
<div class="max-w-md mx-auto">
<div class="flex justify-between items-center mb-6">
    <div class="flex gap-4">
        <a href="{{ url_for('logout') }}" class="px-4 py-2 bg-gray-700 rounded-lg text-sm font-bold text-gray-400 hover:text-white transition">Logout</a>
        <a href="{{ url_for('leaderboard') }}" class="px-4 py-2 bg-yellow-600 rounded-lg text-sm font-black text-white hover:bg-yellow-500 transition shadow-lg">Public Ledger</a>
    </div>
    <div class="text-base font-bold text-gray-400 tracking-wide">{{ user.username }}</div>
</div>

<div class="text-center mb-12 pt-6">
    <h2 class="text-gray-500 uppercase tracking-widest text-sm font-black mb-3">Your Balance</h2>
    <div id="balanceDisplay" class="text-8xl font-black text-white tracking-tighter leading-none drop-shadow-2xl">{{ user.balance | currency }}</div>
</div>

<div class="mb-8">
    <p class="text-sm text-gray-400 mb-3 font-black uppercase tracking-widest">Quick Transfer</p>
    <div class="grid grid-cols-3 gap-3 max-h-64 overflow-y-auto pr-1">
        {% for r in recents %}
        <button onclick="selectUser('{{ r.username }}')" class="bg-gray-700 hover:bg-gray-600 text-white py-5 px-3 rounded-2xl border border-gray-600 transition shadow-md text-lg font-bold truncate w-full transform active:scale-95">
            {{ r.username }}
        </button>
        {% else %}
        <div class="col-span-3 text-center py-4">
             <p class="text-gray-600 text-sm italic">No other users yet.</p>
        </div>
        {% endfor %}
    </div>
</div>

{% if monopoly_mode %}
<div class="mb-8">
    <form action="{{ url_for('pass_go') }}" method="POST">
        <button type="submit" class="w-full bg-yellow-500 hover:bg-yellow-400 text-black font-black py-6 rounded-2xl shadow-2xl transform active:scale-95 transition text-2xl flex justify-center items-center gap-3 border-b-8 border-yellow-700 active:border-b-0">
            <span>🎲</span> PASS GO (+ $200)
        </button>
    </form>
</div>
{% endif %}

<div class="card relative shadow-2xl border border-gray-700/50">
    <h2 class="text-2xl font-black mb-4 text-gray-200">Transfer Funds</h2>
    <form action="{{ url_for('transfer') }}" method="POST" id="transferForm">
        {% if user.is_banker %}
        <div class="mb-4">
            <label class="text-sm font-bold text-gray-500 uppercase tracking-wide ml-1 mb-1 block">From Account</label>
            <select name="source" id="bankerSourceSelect" onchange="checkSource()" class="h-16 text-xl rounded-xl w-full bg-blue-900/30 border border-blue-500/50 text-white font-bold p-4">
                <option value="me">My Personal Account ({{ user.balance | currency }})</option>
                <option value="bank" class="text-yellow-400">🏦 THE BANK</option>
                <option value="parking" class="text-purple-400">🚗 Free Parking</option>
            </select>
        </div>
        {% endif %}
        
        <div class="flex gap-3 items-end mb-4">
            <div class="w-full">
                <label class="text-sm font-bold text-gray-500 uppercase tracking-wide ml-1 mb-1 block">Recipient</label>
                <input type="text" name="recipient" id="recipientInput" value="{{ send_to }}" placeholder="Username" required list="user-suggestions" autocomplete="off" oninput="checkRecipient()" class="h-16 text-xl rounded-xl">
                <datalist id="user-suggestions"></datalist>
            </div>
            
            <!-- Quick Send $1 Button (Initially Hidden) -->
            {% if not monopoly_mode %}
            <button type="button" id="quickSendBtn" onclick="sendOneDollar()" class="hidden bg-green-500 hover:bg-green-600 text-white font-black p-4 rounded-xl mb-4 w-28 h-16 flex items-center justify-center transition-all shadow-xl animate-bounce text-2xl border-b-4 border-green-700 active:border-b-0">
                <span class="mr-1">⚡</span> 1
            </button>
            {% endif %}
        </div>
        
        <label class="text-sm font-bold text-gray-500 uppercase tracking-wide ml-1 mb-1 block">Amount</label>
        <input type="number" name="amount" id="amountInput" step="1" min="1" placeholder="0" required class="h-16 text-2xl rounded-xl font-black">
        
        <button type="submit" class="btn-primary mt-4 py-5 text-xl rounded-xl shadow-lg border-b-4 border-blue-700 active:border-b-0">Send Money</button>
    </form>
</div>

<script>
    // Fetch users for autocomplete
    fetch('{{ url_for("api_users") }}')
        .then(response => response.json())
        .then(data => {
            const list = document.getElementById('user-suggestions');
            data.forEach(user => {
                const option = document.createElement('option');
                option.value = user;
                list.appendChild(option);
            });
        });

    function selectUser(username) {
        const input = document.getElementById('recipientInput');
        input.value = username;
        checkRecipient();
        document.getElementById('amountInput').focus();
    }

    function checkRecipient() {
        const input = document.getElementById('recipientInput');
        const btn = document.getElementById('quickSendBtn');
        if (!btn) return;

        if (input.value.trim().length > 0) {
            btn.classList.remove('hidden');
        } else {
            btn.classList.add('hidden');
        }
    }
    
    function sendOneDollar() {
        const recipient = document.getElementById('recipientInput').value;
        const formData = new FormData();
        formData.append('recipient', recipient);
        formData.append('amount', '1');

        fetch('{{ url_for("transfer") }}', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (!response.ok) return response.json().then(err => { throw err; });
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Update balance on UI instantly
                document.getElementById('balanceDisplay').innerText = '$' + data.new_balance.toLocaleString(undefined, {minimumFractionDigits: 0, maximumFractionDigits: 0});
                
                // Visual pop effect
                const display = document.getElementById('balanceDisplay');
                display.classList.add('text-green-400', 'scale-110');
                setTimeout(() => display.classList.remove('text-green-400', 'scale-110'), 200);
            }
        })
        .catch(error => {
            alert(error.error || "Transfer failed");
        });
    }

    // Run check on load (in case of deep link)
    checkRecipient();

    // Auto-Refresh Logic
    let currentTxId = {{ initial_tx_id }};
    let currentFreeParkingBalance = {{ free_parking_balance if free_parking_balance is not none else 0 }};
    
    function checkSource() {
        const source = document.getElementById('bankerSourceSelect');
        if (source && source.value === 'parking') {
            document.getElementById('amountInput').value = currentFreeParkingBalance;
        } else {
             document.getElementById('amountInput').value = '';
        }
    }

    setInterval(() => {
        // Don't refresh if typing
        if (document.activeElement.tagName === 'INPUT') return;

        fetch('{{ url_for("api_status") }}')
            .then(res => res.json())
            .then(data => {
                if (data.error) return; 
                
                document.getElementById('balanceDisplay').innerText = '$' + data.balance.toLocaleString(undefined, {minimumFractionDigits: 0, maximumFractionDigits: 0});
                
                // Update Free Parking if it exists
                const fpDisplay = document.getElementById('freeParkingDisplay');
                if (data.free_parking_balance !== null) {
                    currentFreeParkingBalance = data.free_parking_balance; // Update global var
                    if (fpDisplay) {
                        fpDisplay.innerText = '$' + data.free_parking_balance.toLocaleString(undefined, {minimumFractionDigits: 0, maximumFractionDigits: 0});
                    }
                }
                
                if (data.last_tx_id > currentTxId) {
                    location.reload();
                }
            });
    }, 3000);
</script>

{% if free_parking_balance is not none %}
<div class="card text-center shadow-xl border-4 border-purple-500/50 bg-purple-900/20 mb-6 py-6">
    <h2 class="text-sm font-black text-purple-400 uppercase tracking-widest mb-1">🚗 Free Parking Pot</h2>
    <div id="freeParkingDisplay" class="text-5xl font-black text-white tracking-tighter">{{ free_parking_balance | currency }}</div>
</div>
{% endif %}

<div class="card text-center shadow-xl border border-gray-700/30">
    <h2 class="text-xl font-black mb-3 text-gray-300 uppercase tracking-widest">Receive Funds</h2>
    <p class="text-sm text-gray-500 mb-4">Show this to another player to get paid</p>
    <div class="bg-white p-4 inline-block rounded-3xl shadow-inner">
        <img src="{{ url_for('qr_image') }}" alt="Your QR Code" class="w-56 h-56">
    </div>
    <p class="text-xs text-gray-600 mt-4 break-all font-mono opacity-50">{{ request_url }}</p>
</div>

<div class="mt-10">
    <h3 class="text-xl font-black mb-4 text-gray-400 uppercase tracking-widest">Transaction History</h3>
    <div class="space-y-3">
        {% for tx in history %}
        <div class="bg-gray-800/80 backdrop-blur-sm p-4 rounded-2xl flex justify-between items-center shadow-lg border border-gray-700/30">
            <div>
                {% if tx.sender == user.username %}
                    <span class="text-red-400 font-bold text-lg">Sent to {{ tx.receiver }}</span>
                {% else %}
                    <span class="text-green-400 font-bold text-lg">Received from {{ tx.sender }}</span>
                {% endif %}
                <div class="text-sm text-gray-600 font-medium">{{ tx.timestamp.strftime('%H:%M:%S') }}</div>
            </div>
            <div class="font-black text-xl {% if tx.sender == user.username %}text-red-400{% else %}text-green-400{% endif %}">
                {% if tx.sender == user.username %}-{% else %}+{% endif %}{{ tx.amount | currency }}
            </div>
        </div>
        {% else %}
        <p class="text-gray-600 text-center py-8 text-lg italic">No activity yet.</p>
        {% endfor %}
    </div>
</div>
</div>
""")

LEADERBOARD_TEMPLATE = HTML_BASE.replace('{% block content %}{% endblock %}', """
<div class="max-w-2xl mx-auto">
    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-black text-yellow-400 tracking-tight uppercase">Public Ledger</h1>
        <a href="{{ url_for('index') }}" class="px-6 py-3 bg-gray-700 rounded-xl text-lg font-bold text-gray-300 hover:bg-gray-600 transition">Back</a>
    </div>

    <div class="card mb-8 shadow-2xl border border-gray-700">
        <h2 class="text-2xl font-black mb-6 text-gray-200 uppercase tracking-widest">Wealth Distribution</h2>
        <div class="relative h-80 w-full">
            <canvas id="wealthChart"></canvas>
        </div>
    </div>

    <div class="card shadow-2xl border border-gray-700">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-black text-white uppercase tracking-widest">Rich List</h2>
            <div class="text-sm text-gray-500 font-bold uppercase tracking-widest">Total: <span class="text-green-400 text-xl">{{ total_circulation | currency }}</span></div>
        </div>
        <div class="overflow-y-auto">
            <table class="w-full text-lg text-left text-gray-400">
                <thead class="text-sm text-gray-200 uppercase bg-gray-700">
                    <tr>
                        <th class="px-4 py-3">Rank</th>
                        <th class="px-4 py-3">User</th>
                        <th class="px-4 py-3 text-right">Balance</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                    {% for u in users %}
                    <tr class="{% if u.username == 'Bank' %}bg-blue-900/30{% endif %} hover:bg-gray-700/50 transition">
                        <td class="px-4 py-5 font-black text-gray-500">#{{ loop.index }}</td>
                        <td class="px-4 py-5 font-black text-white text-xl">
                            {{ u.username }}
                            {% if u.username == 'Bank' %} <span class="text-xs text-blue-400 ml-2 border border-blue-400 px-2 py-0.5 rounded-full">SYSTEM</span>{% endif %}
                        </td>
                        <td class="px-4 py-5 text-right text-green-400 font-black text-2xl">{{ u.balance | currency }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    const ctx = document.getElementById('wealthChart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: {{ chart_labels | safe }},
            datasets: [{
                data: {{ chart_data | safe }},
                backgroundColor: [
                    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', 
                    '#ec4899', '#6366f1', '#14b8a6', '#f97316', '#84cc16'
                ],
                borderWidth: 2,
                borderColor: '#2d3748'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { 
                        color: '#9ca3af',
                        font: { size: 14, weight: 'bold' }
                    }
                }
            }
        }
    });
</script>
""")

ADMIN_LOGIN_TEMPLATE = HTML_BASE.replace('{% block content %}{% endblock %}', """
<div class="card text-center mt-10 max-w-md mx-auto">
    <h1 class="text-3xl font-black mb-8 text-red-500 uppercase tracking-widest">Admin Access</h1>
    <form action="{{ url_for('admin') }}" method="POST">
        <input type="password" name="password" placeholder="Password" required class="text-center h-16 text-2xl rounded-xl">
        <button type="submit" class="btn-danger mt-6 py-5 text-xl rounded-xl shadow-lg">Authenticate</button>
    </form>
</div>
""")

ADMIN_DASHBOARD_TEMPLATE = HTML_BASE.replace('{% block content %}{% endblock %}', """
<div class="flex justify-between items-center mb-10">
    <h1 class="text-5xl font-black text-red-500 uppercase tracking-tighter">Admin Terminal</h1>
    <a href="{{ url_for('index') }}" class="px-10 py-5 bg-gray-700 rounded-2xl text-xl font-black text-gray-300 hover:bg-gray-600 transition shadow-2xl border-b-4 border-gray-800 active:border-b-0">USER VIEW</a>
</div>

<!-- Top Row: Stats and Toggles -->
<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
    <div class="card border-l-8 border-green-500 flex flex-col justify-center py-6">
        <p class="text-xs font-black text-gray-500 uppercase tracking-widest mb-1">Circulation</p>
        <p class="text-4xl font-black text-green-400 tracking-tighter">{{ total_circulation | currency }}</p>
    </div>
    <div class="card border-l-8 border-blue-500 flex flex-col justify-center py-6">
        <p class="text-xs font-black text-gray-500 uppercase tracking-widest mb-1">Active Users</p>
        <p class="text-4xl font-black text-white tracking-tighter">{{ user_stats|length }}</p>
    </div>
    <div class="card md:col-span-2 flex items-center justify-between py-6">
        <div>
            <p class="text-xs font-black text-gray-500 uppercase tracking-widest mb-1">Game Mode</p>
            <p class="text-xl font-black text-white">Monopoly Rules</p>
        </div>
        <div class="flex gap-4">
            {% if monopoly_mode %}
            <form action="{{ url_for('admin_action') }}" method="POST">
                <input type="hidden" name="action" value="create_free_parking">
                <button type="submit" class="px-6 py-4 bg-purple-600 hover:bg-purple-500 text-white rounded-xl font-black transition-all text-sm shadow-lg border-b-4 border-purple-800 active:border-b-0 uppercase tracking-wide">
                    + Free Parking
                </button>
            </form>
            {% endif %}
            <form action="{{ url_for('admin_toggle_monopoly') }}" method="POST">
                <button type="submit" class="px-8 py-4 rounded-xl font-black transition-all text-lg {{ 'bg-yellow-500 text-black shadow-lg shadow-yellow-500/40' if monopoly_mode else 'bg-gray-700 text-gray-400' }}">
                    {{ 'ENABLED' if monopoly_mode else 'DISABLED' }}
                </button>
            </form>
        </div>
    </div>
</div>

<!-- Middle Row: Manage Funds (Full Width) -->
<div class="card shadow-2xl border border-gray-700/50 mb-8">
    <h2 class="text-2xl font-black mb-8 text-gray-200 uppercase tracking-widest">Global Fund Management</h2>
    <form action="{{ url_for('admin_action') }}" method="POST">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <!-- Sender -->
            <div>
                <label class="block text-sm font-black text-gray-500 mb-3 uppercase tracking-widest ml-1">From (Sender)</label>
                <select name="sender" id="senderSelect" onchange="checkAdminSender()" class="bg-gray-700 text-white rounded-2xl p-5 h-20 w-full text-3xl font-bold border-2 border-transparent focus:border-red-500 transition shadow-inner">
                    <option value="MINT" class="text-green-400 font-black">MINT (CREATE)</option>
                    <option value="SET_BALANCE" class="text-blue-400 font-black">SET BALANCE</option>
                    <option value="Bank" selected>BANK</option>
                    {% for u in all_users if u != 'Bank' %}
                    <option value="{{ u }}">{{ u }}</option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Receiver -->
            <div>
                <label class="block text-sm font-black text-gray-500 mb-3 uppercase tracking-widest ml-1">To (Receiver)</label>
                <select name="receiver" id="receiverSelect" class="bg-gray-700 text-white rounded-2xl p-5 h-20 w-full text-3xl font-bold border-2 border-transparent focus:border-red-500 transition shadow-inner">
                     <option value="BURN" class="text-red-400 font-black">BURN (DESTROY)</option>
                     {% for u in all_users %}
                     <option value="{{ u }}">{{ u }}</option>
                     {% endfor %}
                </select>
            </div>

            <!-- Amount -->
            <div>
                <label class="block text-sm font-black text-gray-500 mb-3 uppercase tracking-widest ml-1">Amount</label>
                <input type="number" name="amount" id="amountInput" placeholder="0" step="1" required class="bg-gray-700 text-white rounded-2xl p-5 h-20 w-full text-3xl font-black border-2 border-transparent focus:border-red-500 transition shadow-inner">
            </div>
        </div>
        
        <button type="submit" class="w-full bg-red-600 hover:bg-red-500 text-white h-24 text-3xl font-black rounded-3xl shadow-2xl transition-all transform active:scale-[0.99] border-b-8 border-red-800 active:border-b-0 uppercase tracking-widest">Execute Transaction</button>
    </form>
</div>

<!-- Bottom Row: User List and Danger Zone -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-8">
    <!-- User List (2/3 width) -->
    <div class="card md:col-span-2 shadow-2xl">
        <h2 class="text-2xl font-black mb-6 text-white uppercase tracking-widest">User Directory <span class="text-sm text-gray-500 font-bold block">CLICK ANY ROW TO TARGET FOR RECEIPT</span></h2>
        <div class="overflow-y-auto max-h-[40rem] rounded-2xl border border-gray-700">
            <table class="w-full text-left text-gray-400">
                <thead class="text-sm text-gray-200 uppercase bg-gray-700 sticky top-0">
                    <tr>
                        <th class="px-8 py-5">User</th>
                        <th class="px-8 py-5 text-right">Balance</th>
                        <th class="px-8 py-5 text-right">Role</th>
                        <th class="px-8 py-5 text-right">Activity</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700 bg-gray-800/50">
                    {% for stat in user_stats %}
                    <tr class="hover-row transition duration-150 active:bg-red-900/30 group" onclick="fillUser('{{ stat.username }}')">
                        <td class="px-8 py-8 font-black text-white text-3xl group-hover:text-red-400 transition">{{ stat.username }}</td>
                        <td class="px-8 py-8 text-right text-green-400 font-black text-4xl">{{ stat.balance | currency }}</td>
                        <td class="px-8 py-8 text-right" onclick="event.stopPropagation()">
                             {% if stat.username != 'Bank' %}
                             <form action="{{ url_for('admin_toggle_banker') }}" method="POST">
                                <input type="hidden" name="username" value="{{ stat.username }}">
                                <button type="submit" class="px-3 py-1 rounded text-xs font-bold uppercase {{ 'bg-blue-600 text-white' if stat.is_banker else 'bg-gray-700 text-gray-500' }}">
                                    {{ 'BANKER' if stat.is_banker else 'PLAYER' }}
                                </button>
                             </form>
                             {% else %}
                             <span class="text-blue-400 font-bold">SYSTEM</span>
                             {% endif %}
                        </td>
                        <td class="px-8 py-8 text-right text-xl font-bold text-gray-500">{{ stat.tx_count }} tx</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Danger Zone (1/3 width) -->
    <div class="card md:col-span-1 border-4 border-red-900 bg-red-950/20 shadow-2xl flex flex-col">
        <h2 class="text-3xl font-black mb-6 text-red-500 uppercase tracking-tighter">Danger Zone</h2>
        <p class="text-lg text-gray-400 mb-10 font-bold leading-tight border-b border-red-900/50 pb-6">Critical administrative overrides. These actions cannot be undone.</p>
        
        <!-- Delete User Form -->
        <div class="mb-12">
            <label class="block text-sm font-black text-red-900 mb-4 uppercase tracking-widest">Terminate Account</label>
            <form action="{{ url_for('admin_action') }}" method="POST" onsubmit="return confirm('Are you sure you want to PERMANENTLY delete this user?');">
                <input type="hidden" name="action" value="delete_user">
                <div class="space-y-4">
                    <select name="username" class="bg-gray-900 text-red-500 rounded-2xl p-5 h-20 w-full text-3xl font-black border-2 border-red-900 shadow-inner" required>
                        <option value="" disabled selected>SELECT TARGET</option>
                        {% for u in all_users if u != 'Bank' %}
                        <option value="{{ u }}">{{ u }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-red-900 hover:bg-red-800 text-white py-5 rounded-2xl font-black uppercase text-xl transition shadow-xl border-b-4 border-red-950 active:border-b-0">DELETE USER</button>
                </div>
            </form>
        </div>

        <div class="mt-auto pt-10 border-t border-red-900/50">
            <label class="block text-sm font-black text-red-900 mb-4 uppercase tracking-widest">System Override</label>
            <form action="{{ url_for('admin_action') }}" method="POST" onsubmit="return confirm('Are you sure you want to WIPE the database?');">
                <input type="hidden" name="action" value="reset">
                <input type="hidden" name="confirm" value="yes">
                <button type="submit" class="w-full bg-red-600 hover:bg-red-500 text-white py-8 text-2xl font-black rounded-3xl shadow-2xl border-b-8 border-red-900 active:border-b-0 transition-all uppercase tracking-widest">NUKE DATABASE</button>
            </form>
        </div>
    </div>
</div>

<!-- Transaction Log -->
<div class="card shadow-2xl border border-gray-700/50 mt-8">
    <h2 class="text-2xl font-black mb-6 text-white uppercase tracking-widest">System Transaction Log</h2>
    <div class="overflow-y-auto max-h-[32rem] rounded-xl">
        <table class="w-full text-left text-gray-400">
            <thead class="text-sm text-gray-200 uppercase bg-gray-700 sticky top-0">
                <tr>
                    <th class="px-6 py-4">Time</th>
                    <th class="px-6 py-4">From</th>
                    <th class="px-6 py-4">To</th>
                    <th class="px-6 py-4 text-right">Amount</th>
                    <th class="px-6 py-4 text-right">Note</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-700 bg-gray-800/50">
                {% for tx in transactions %}
                <tr class="hover:bg-gray-700/30 transition">
                    <td class="px-6 py-4 text-sm font-mono text-gray-500">{{ tx.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                    <td class="px-6 py-4 font-bold text-white">{{ tx.sender or 'SYSTEM' }}</td>
                    <td class="px-6 py-4 font-bold text-white">{{ tx.receiver }}</td>
                    <td class="px-6 py-4 text-right font-black {{ 'text-green-400' if tx.sender == 'MINT' else 'text-white' }}">{{ tx.amount | currency }}</td>
                    <td class="px-6 py-4 text-right text-xs text-gray-500 uppercase tracking-wide">{{ tx.note }}</td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="5" class="px-6 py-8 text-center text-gray-500 italic">No transactions recorded.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<script>
    function fillUser(username) {
        const select = document.getElementById('receiverSelect');
        select.value = username;
        select.classList.add('ring-8', 'ring-red-500/50');
        setTimeout(() => select.classList.remove('ring-8', 'ring-red-500/50'), 500);
        document.getElementById('amountInput').focus();
    }

    function checkAdminSender() {
        const sender = document.getElementById('senderSelect').value;
        if (sender === 'Free Parking') {
            document.getElementById('amountInput').value = {{ free_parking_balance }};
        } else {
             document.getElementById('amountInput').value = '';
        }
    }
</script>
""")

# --- Startup ---

def print_startup_qr():
    ip = get_local_ip()
    url = f"http://{ip}:5000"
    print("\n" + "="*40)
    print(f"Server running at: {url}")
    print("Scan this QR code to connect:")
    print("="*40 + "\n")
    
    qr = qrcode.QRCode()
    qr.add_data(url)
    qr.print_ascii(tty=True)
    print("\n" + "="*40 + "\n")


def init_db():
    with app.app_context():
        db.create_all()
        
        # Migration: Add new columns if missing
        with db.engine.connect() as conn:
            # Check for is_banker
            try:
                conn.execute(db.text("ALTER TABLE user ADD COLUMN is_banker BOOLEAN DEFAULT 0"))
                print("Added is_banker column")
            except Exception:
                pass # Column likely exists
            
            # Check for color
            try:
                conn.execute(db.text("ALTER TABLE user ADD COLUMN color VARCHAR(20) DEFAULT '#3b82f6'"))
                print("Added color column")
            except Exception:
                pass # Column likely exists
        
        # Create Bank user if not exists
        if not User.query.filter_by(username='Bank').first():
            bank = User(username='Bank', balance=0, color='#1e3a8a', is_banker=True)
            db.session.add(bank)
            db.session.commit()
            print("Bank user initialized.")

if __name__ == '__main__':
    init_db()
    
    print_startup_qr()
    app.run(host='0.0.0.0', port=5000, debug=False)

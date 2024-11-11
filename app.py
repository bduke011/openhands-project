from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
import csv
from io import StringIO
from collections import defaultdict
from flask import send_file
from dotenv import load_dotenv

load_dotenv()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cashflow.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Add datetime functions to template context
@app.context_processor
def utility_processor():
    return {
        'now': datetime.utcnow,
        'timedelta': timedelta
    }

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    devices = db.relationship('Device', backref='location', lazy=True)

class GameType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'texas_skill_1'
    name = db.Column(db.String(100), nullable=False)  # e.g., 'Texas Skill 1'
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    devices = db.relationship('Device', backref='game_type_info', lazy=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)
    device_type = db.Column(db.String(20), nullable=False)  # 'slot' or 'redemption'
    game_type_id = db.Column(db.Integer, db.ForeignKey('game_type.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    transactions = db.relationship('Transaction', backref='device', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_collection = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')  # 'active', 'inactive', 'maintenance'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'collection', 'deposit', 'free_play'
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_admin:
        locations = Location.query.all()
        return render_template('admin_dashboard.html', locations=locations)
    return render_template('user_dashboard.html')

@app.route('/transaction/new', methods=['GET', 'POST'])
@login_required
def new_transaction():
    if request.method == 'POST':
        device_id = request.form.get('device_id')
        amount = float(request.form.get('amount'))
        transaction_type = request.form.get('transaction_type')
        
        transaction = Transaction(
            device_id=device_id,
            amount=amount,
            transaction_type=transaction_type,
            user_id=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()
        flash('Transaction recorded successfully')
        return redirect(url_for('dashboard'))
    
    devices = Device.query.all()
    return render_template('new_transaction.html', devices=devices)

@app.route('/reports')
@login_required
@admin_required
def reports():
    locations = Location.query.all()
    return render_template('reports.html', locations=locations)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/new', methods=['POST'])
@login_required
@admin_required
def new_user():
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'true'
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
        
    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/admin/locations')
@login_required
@admin_required
def manage_locations():
    locations = Location.query.all()
    return render_template('admin/locations.html', locations=locations)

@app.route('/admin/locations/new', methods=['POST'])
@login_required
@admin_required
def new_location():
    name = request.form.get('name')
    
    if Location.query.filter_by(name=name).first():
        return jsonify({'error': 'Location already exists'}), 400
        
    location = Location(name=name)
    db.session.add(location)
    db.session.commit()
    
    return jsonify({'message': 'Location created successfully', 'id': location.id})

@app.route('/admin/locations/<int:location_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_location(location_id):
    location = Location.query.get_or_404(location_id)
    
    if location.devices:
        return jsonify({'error': 'Cannot delete location with associated devices'}), 400
    
    db.session.delete(location)
    db.session.commit()
    return jsonify({'message': 'Location deleted successfully'})

@app.route('/admin/devices')
@login_required
@admin_required
def manage_devices():
    devices = Device.query.all()
    locations = Location.query.all()
    game_types = GameType.query.filter_by(is_active=True).all()
    return render_template('admin/devices.html', 
                         devices=devices, 
                         locations=locations,
                         game_types=game_types)

@app.route('/admin/game-types')
@login_required
@admin_required
def manage_game_types():
    game_types = GameType.query.order_by(GameType.created_at.desc()).all()
    return render_template('admin/game_types.html', game_types=game_types)

@app.route('/admin/game-types/new', methods=['POST'])
@login_required
@admin_required
def new_game_type():
    code = request.form.get('code')
    name = request.form.get('name')
    description = request.form.get('description')
    
    if GameType.query.filter_by(code=code).first():
        return jsonify({'error': 'Game type code already exists'}), 400
        
    game_type = GameType(
        code=code,
        name=name,
        description=description
    )
    db.session.add(game_type)
    db.session.commit()
    
    return jsonify({
        'message': 'Game type created successfully',
        'id': game_type.id,
        'name': game_type.name
    })

@app.route('/admin/game-types/<int:game_type_id>', methods=['PUT'])
@login_required
@admin_required
def update_game_type(game_type_id):
    game_type = GameType.query.get_or_404(game_type_id)
    
    if 'is_active' in request.json:
        game_type.is_active = request.json['is_active']
    if 'name' in request.json:
        game_type.name = request.json['name']
    if 'description' in request.json:
        game_type.description = request.json['description']
        
    db.session.commit()
    return jsonify({'message': 'Game type updated successfully'})

@app.route('/admin/game-types/<int:game_type_id>/performance')
@login_required
@admin_required
def game_type_performance(game_type_id):
    game_type = GameType.query.get_or_404(game_type_id)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Default to last 30 days if no date range provided
    if not start_date or not end_date:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
    else:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    
    # Get all transactions for this game type's devices in the date range
    transactions = Transaction.query.join(Device).filter(
        Device.game_type_id == game_type_id,
        Transaction.timestamp.between(start_date, end_date)
    ).order_by(Transaction.timestamp.desc()).all()
    
    # Calculate performance metrics
    performance_data = calculate_game_type_performance(transactions, game_type, start_date, end_date)
    
    return render_template(
        'admin/game_type_performance.html',
        game_type=game_type,
        performance=performance_data,
        start_date=start_date,
        end_date=end_date
    )

@app.route('/admin/game-types/export')
@login_required
@admin_required
def export_game_type_performance():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    game_type_id = request.args.get('game_type_id')
    
    if not start_date or not end_date:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
    else:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    
    query = Transaction.query.join(Device).join(GameType)
    
    if game_type_id:
        query = query.filter(Device.game_type_id == game_type_id)
    
    query = query.filter(Transaction.timestamp.between(start_date, end_date))
    transactions = query.order_by(Transaction.timestamp.desc()).all()
    
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        'Date', 'Location', 'Game Type', 'Serial Number', 
        'Transaction Type', 'Amount', 'User', 'Device Status'
    ])
    
    for t in transactions:
        writer.writerow([
            t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            t.device.location.name,
            t.device.game_type_info.name if t.device.game_type_info else 'N/A',
            t.device.serial_number,
            t.transaction_type,
            f"${t.amount:.2f}",
            t.user.username,
            t.device.status
        ])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        StringIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'game_performance_{datetime.now().strftime("%Y%m%d")}.csv'
    )

def calculate_game_type_performance(transactions, game_type, start_date, end_date):
    """Calculate detailed performance metrics for a game type."""
    days = (end_date - start_date).days
    
    # Group transactions by location
    location_stats = defaultdict(lambda: {
        'collections': 0,
        'free_play': 0,
        'device_count': 0,
        'active_days': set(),
        'transactions_count': 0
    })
    
    # Get all devices for this game type
    devices = Device.query.filter_by(game_type_id=game_type.id).all()
    
    # Initialize device counts
    for device in devices:
        location_stats[device.location.name]['device_count'] += 1
    
    # Process transactions
    for t in transactions:
        location = t.device.location.name
        location_stats[location]['transactions_count'] += 1
        location_stats[location]['active_days'].add(t.timestamp.date())
        
        if t.transaction_type == 'collection':
            location_stats[location]['collections'] += t.amount
        elif t.transaction_type == 'free_play':
            location_stats[location]['free_play'] += t.amount
    
    # Calculate metrics for each location
    performance_data = {
        'locations': {},
        'total_collections': 0,
        'total_free_play': 0,
        'total_devices': 0,
        'total_transactions': 0,
        'days_analyzed': days
    }
    
    for location, stats in location_stats.items():
        net_profit = stats['collections'] - stats['free_play']
        active_days = len(stats['active_days'])
        
        location_metrics = {
            'collections': stats['collections'],
            'free_play': stats['free_play'],
            'net_profit': net_profit,
            'device_count': stats['device_count'],
            'transactions_count': stats['transactions_count'],
            'active_days': active_days,
            'daily_average': net_profit / days if days > 0 else 0,
            'per_device_average': net_profit / stats['device_count'] if stats['device_count'] > 0 else 0,
            'utilization_rate': (active_days / days * 100) if days > 0 else 0
        }
        
        performance_data['locations'][location] = location_metrics
        performance_data['total_collections'] += stats['collections']
        performance_data['total_free_play'] += stats['free_play']
        performance_data['total_devices'] += stats['device_count']
        performance_data['total_transactions'] += stats['transactions_count']
    
    # Calculate overall metrics
    performance_data['total_net_profit'] = performance_data['total_collections'] - performance_data['total_free_play']
    performance_data['daily_average'] = performance_data['total_net_profit'] / days if days > 0 else 0
    performance_data['per_device_average'] = (
        performance_data['total_net_profit'] / performance_data['total_devices'] 
        if performance_data['total_devices'] > 0 else 0
    )
    
    return performance_data

@app.route('/admin/devices/new', methods=['POST'])
@login_required
@admin_required
def new_device():
    serial_number = request.form.get('serial_number')
    device_type = request.form.get('device_type')
    location_id = request.form.get('location_id')
    game_type_id = request.form.get('game_type_id')
    
    if Device.query.filter_by(serial_number=serial_number).first():
        return jsonify({'error': 'Serial number already exists'}), 400
    
    # Validate game type for slot machines
    if device_type == 'slot' and not game_type_id:
        return jsonify({'error': 'Game type is required for slot machines'}), 400
    
    # Validate game type exists if provided
    if game_type_id and not GameType.query.get(game_type_id):
        return jsonify({'error': 'Invalid game type selected'}), 400
        
    device = Device(
        serial_number=serial_number,
        device_type=device_type,
        location_id=location_id,
        game_type_id=game_type_id if device_type == 'slot' else None,
        status='active'
    )
    db.session.add(device)
    db.session.commit()
    
    return jsonify({'message': 'Device created successfully', 'id': device.id})

@app.route('/admin/devices/<int:device_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    if device.transactions:
        return jsonify({'error': 'Cannot delete device with associated transactions'}), 400
    
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': 'Device deleted successfully'})

@app.route('/admin/summary')
@login_required
@admin_required
def admin_summary():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    
    transactions = Transaction.query.filter(
        Transaction.timestamp.between(start_date, end_date)
    ).all()
    
    summary = calculate_summary(transactions)
    
    # Calculate per-location summaries
    location_summaries = {}
    for location in Location.query.all():
        location_transactions = [t for t in transactions if t.device.location_id == location.id]
        if location_transactions:
            location_summaries[location.name] = calculate_summary(location_transactions)
    
    return render_template('admin/summary.html', 
                         summary=summary, 
                         location_summaries=location_summaries,
                         start_date=start_date, 
                         end_date=end_date)

@app.route('/admin/export/transactions')
@login_required
@admin_required
def export_transactions():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    location_id = request.args.get('location_id')
    
    query = Transaction.query
    
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(Transaction.timestamp.between(start, end))
    
    if location_id:
        query = query.join(Device).filter(Device.location_id == location_id)
    
    transactions = query.order_by(Transaction.timestamp.desc()).all()
    
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Date', 'Location', 'Device Type', 'Serial Number', 'Transaction Type', 'Amount', 'User'])
    
    for t in transactions:
        writer.writerow([
            t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            t.device.location.name,
            t.device.device_type,
            t.device.serial_number,
            t.transaction_type,
            f"${t.amount:.2f}",
            t.user.username
        ])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        StringIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'transactions_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/admin/reports/device-performance')
@login_required
@admin_required
def device_performance():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)  # Last 30 days by default
    
    transactions = Transaction.query.filter(
        Transaction.timestamp.between(start_date, end_date)
    ).all()
    
    device_stats = defaultdict(lambda: {
        'collections': 0,
        'deposits': 0,
        'free_play': 0,
        'transaction_count': 0,
        'location': '',
        'device_type': '',
        'serial_number': ''
    })
    
    for t in transactions:
        stats = device_stats[t.device_id]
        stats['location'] = t.device.location.name
        stats['device_type'] = t.device.device_type
        stats['serial_number'] = t.device.serial_number
        stats['transaction_count'] += 1
        
        if t.transaction_type == 'collection':
            stats['collections'] += t.amount
        elif t.transaction_type == 'deposit':
            stats['deposits'] += t.amount
        elif t.transaction_type == 'free_play':
            stats['free_play'] += t.amount
    
    # Convert to list and calculate net revenue
    performance_data = []
    for device_id, stats in device_stats.items():
        stats['net_revenue'] = stats['collections'] - stats['deposits'] - stats['free_play']
        stats['avg_transaction'] = stats['collections'] / stats['transaction_count'] if stats['transaction_count'] > 0 else 0
        performance_data.append(stats)
    
    # Sort by net revenue
    performance_data.sort(key=lambda x: x['net_revenue'], reverse=True)
    
    return render_template('admin/device_performance.html',
                         performance_data=performance_data,
                         start_date=start_date,
                         end_date=end_date)

def calculate_summary(transactions):
    return {
        'total_collections': sum(t.amount for t in transactions if t.transaction_type == 'collection'),
        'total_deposits': sum(t.amount for t in transactions if t.transaction_type == 'deposit'),
        'total_free_play': sum(t.amount for t in transactions if t.transaction_type == 'free_play'),
        'net_cash_flow': sum(t.amount for t in transactions if t.transaction_type == 'collection') - 
                        sum(t.amount for t in transactions if t.transaction_type == 'deposit'),
        'transaction_count': len(transactions)
    }

def init_db():
    """Initialize database with default data."""
    db.create_all()

    # Create admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

    # Create default game types if they don't exist
    default_game_types = [
        {
            'code': 'texas_skill_1',
            'name': 'Texas Skill 1',
            'description': 'Texas Skill Game Type 1'
        },
        {
            'code': 'texas_skill_2',
            'name': 'Texas Skill 2',
            'description': 'Texas Skill Game Type 2'
        },
        {
            'code': 'texas_skill_3',
            'name': 'Texas Skill 3',
            'description': 'Texas Skill Game Type 3'
        }
    ]

    for game_type_data in default_game_types:
        if not GameType.query.filter_by(code=game_type_data['code']).first():
            game_type = GameType(**game_type_data)
            db.session.add(game_type)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error creating default game types: {e}")

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
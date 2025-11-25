# Импорт необходимых библиотек Flask для работы веб-приложения
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
# Импорт SQLAlchemy для работы с базой данных
from flask_sqlalchemy import SQLAlchemy
# Импорт функций для хеширования и проверки паролей (безопасное хранение)
from werkzeug.security import generate_password_hash, check_password_hash
# Импорт datetime для работы с датами и временем
from datetime import datetime, timedelta
# Импорт модуля логирования для записи событий приложения
import logging
from functools import wraps

# Настройка системы логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('todo_app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Создание экземпляра Flask приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация объекта базы данных SQLAlchemy
db = SQLAlchemy(app)

# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========

# Модель User - таблица пользователей в базе данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'admin', 'deputy_admin' или 'user'
    points = db.Column(db.Integer, default=0, nullable=False)  # Баллы пользователя
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Связи
    created_tasks = db.relationship('Task', foreign_keys='Task.creator_id', backref='creator', lazy=True)
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assignee_id', backref='assignee', lazy=True)
    activities = db.relationship('Activity', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'
    
    def is_deputy_admin(self):
        return self.role == 'deputy_admin'
    
    def is_admin_or_deputy(self):
        """Проверка, является ли пользователь админом или зам админом"""
        return self.role in ['admin', 'deputy_admin']
    
    def is_super_admin(self):
        """Проверка, является ли пользователь супер-админом (только админ, не зам)"""
        return self.role == 'admin'

    def add_points(self, points):
        """Добавить баллы пользователю"""
        self.points += points
        db.session.commit()

# Модель Task - таблица задач в базе данных
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='new', nullable=False)  # new, in_progress, completed, cancelled
    priority = db.Column(db.String(20), default='medium', nullable=False)  # low, medium, high, urgent
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deadline = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    # Связи
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    activities = db.relationship('Activity', backref='task', lazy=True, cascade='all, delete-orphan')

    def is_completed(self):
        return self.status == 'completed'

    def is_overdue(self):
        if self.deadline and self.status != 'completed':
            return datetime.utcnow() > self.deadline
        return False

# Модель Activity - таблица активности/отчетов
class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)  # created, assigned, updated, completed, etc.
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Связи
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=True)

# ========== ДЕКОРАТОРЫ ДЛЯ ПРОВЕРКИ ПРАВ ==========

def login_required(f):
    """Декоратор для проверки авторизации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Декоратор для проверки прав администратора или зам админа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'error')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin_or_deputy():
            flash('У вас нет прав для доступа к этой странице', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    """Декоратор для проверки прав супер-администратора (только админ, не зам)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'error')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_super_admin():
            flash('Только главный администратор может выполнять это действие', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ========== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ==========
def migrate_database():
    """Миграция базы данных: добавление новых колонок если их нет"""
    from sqlalchemy import inspect, text
    
    inspector = inspect(db.engine)
    
    # Проверяем таблицу user
    if 'user' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('user')]
        
        # Добавляем колонку role если её нет
        if 'role' not in columns:
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT "user"'))
                db.session.commit()
                logger.info("Добавлена колонка 'role' в таблицу 'user'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'role': {e}")
                db.session.rollback()
        
        # Добавляем колонку points если её нет
        if 'points' not in columns:
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN points INTEGER DEFAULT 0'))
                db.session.commit()
                logger.info("Добавлена колонка 'points' в таблицу 'user'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'points': {e}")
                db.session.rollback()
        
        # Обновляем существующих пользователей: устанавливаем role='user' если NULL
        try:
            db.session.execute(text('UPDATE user SET role = "user" WHERE role IS NULL'))
            db.session.execute(text('UPDATE user SET points = 0 WHERE points IS NULL'))
            db.session.commit()
        except Exception as e:
            logger.warning(f"Ошибка при обновлении данных пользователей: {e}")
            db.session.rollback()
    
    # Проверяем таблицу todo (старая) и переименовываем/создаем task
    table_names = inspector.get_table_names()
    if 'todo' in table_names and 'task' not in table_names:
        try:
            # Получаем колонки до переименования
            todo_columns = [col['name'] for col in inspector.get_columns('todo')]
            has_completed = 'completed' in todo_columns
            has_user_id = 'user_id' in todo_columns
            
            # Переименовываем todo в task
            db.session.execute(text('ALTER TABLE todo RENAME TO task'))
            db.session.commit()
            
            # Теперь проверяем колонки task
            task_columns = [col['name'] for col in inspector.get_columns('task')]
            
            # Добавляем новые колонки
            if 'status' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN status VARCHAR(20) DEFAULT "new"'))
            if 'priority' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN priority VARCHAR(20) DEFAULT "medium"'))
            if 'deadline' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN deadline DATETIME'))
            if 'completed_at' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN completed_at DATETIME'))
            if 'assignee_id' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN assignee_id INTEGER'))
            
            # Переименовываем user_id в creator_id если нужно
            if has_user_id and 'creator_id' not in task_columns:
                db.session.execute(text('ALTER TABLE task ADD COLUMN creator_id INTEGER'))
                db.session.execute(text('UPDATE task SET creator_id = user_id'))
            
            # Обновляем статусы: completed -> completed, остальные -> new
            if has_completed:
                db.session.execute(text('UPDATE task SET status = CASE WHEN completed = 1 THEN "completed" ELSE "new" END'))
            else:
                # Если нет completed, устанавливаем все как new
                db.session.execute(text('UPDATE task SET status = "new" WHERE status IS NULL OR status = ""'))
            
            # Устанавливаем приоритет по умолчанию
            db.session.execute(text('UPDATE task SET priority = "medium" WHERE priority IS NULL OR priority = ""'))
            
            db.session.commit()
            logger.info("Таблица 'todo' мигрирована в 'task'")
        except Exception as e:
            logger.warning(f"Ошибка при миграции таблицы todo: {e}")
            db.session.rollback()
    
    # Проверяем таблицу task и добавляем недостающие колонки
    if 'task' in inspector.get_table_names():
        task_columns = [col['name'] for col in inspector.get_columns('task')]
        
        if 'status' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN status VARCHAR(20) DEFAULT "new"'))
                db.session.commit()
                logger.info("Добавлена колонка 'status' в таблицу 'task'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'status': {e}")
                db.session.rollback()
        
        if 'priority' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN priority VARCHAR(20) DEFAULT "medium"'))
                db.session.commit()
                logger.info("Добавлена колонка 'priority' в таблицу 'task'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'priority': {e}")
                db.session.rollback()
        
        if 'deadline' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN deadline DATETIME'))
                db.session.commit()
                logger.info("Добавлена колонка 'deadline' в таблицу 'task'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'deadline': {e}")
                db.session.rollback()
        
        if 'completed_at' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN completed_at DATETIME'))
                db.session.commit()
                logger.info("Добавлена колонка 'completed_at' в таблицу 'task'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'completed_at': {e}")
                db.session.rollback()
        
        if 'assignee_id' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN assignee_id INTEGER'))
                db.session.commit()
                logger.info("Добавлена колонка 'assignee_id' в таблицу 'task'")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'assignee_id': {e}")
                db.session.rollback()
        
        # Если есть user_id но нет creator_id, создаем creator_id и копируем данные
        if 'user_id' in task_columns and 'creator_id' not in task_columns:
            try:
                db.session.execute(text('ALTER TABLE task ADD COLUMN creator_id INTEGER'))
                db.session.execute(text('UPDATE task SET creator_id = user_id WHERE creator_id IS NULL'))
                db.session.commit()
                logger.info("Добавлена колонка 'creator_id' в таблицу 'task' и скопированы данные из user_id")
            except Exception as e:
                logger.warning(f"Ошибка при добавлении колонки 'creator_id': {e}")
                db.session.rollback()
        
        # Если есть creator_id но он NULL, заполняем из user_id (если есть)
        if 'creator_id' in task_columns and 'user_id' in task_columns:
            try:
                db.session.execute(text('UPDATE task SET creator_id = user_id WHERE creator_id IS NULL AND user_id IS NOT NULL'))
                db.session.commit()
            except Exception as e:
                logger.warning(f"Ошибка при заполнении creator_id: {e}")
                db.session.rollback()
        
        # Если есть колонка completed (boolean), преобразуем её в status
        if 'completed' in task_columns and 'status' in task_columns:
            try:
                db.session.execute(text('UPDATE task SET status = CASE WHEN completed = 1 THEN "completed" ELSE "new" END WHERE status IS NULL OR status = ""'))
                db.session.commit()
                logger.info("Преобразованы данные из колонки 'completed' в 'status'")
            except Exception as e:
                logger.warning(f"Ошибка при преобразовании completed в status: {e}")
                db.session.rollback()

with app.app_context():
    # Выполняем миграцию перед созданием таблиц
    migrate_database()
    # Создаем все таблицы (если их еще нет)
    db.create_all()
    # Создаем администратора, если его нет
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logger.info("Создан администратор: admin / admin123")
    except Exception as e:
        logger.error(f"Ошибка при создании администратора: {e}")
        db.session.rollback()
    logger.info("База данных инициализирована")

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def create_activity(user_id, action, description, task_id=None):
    """Создать запись активности"""
    activity = Activity(
        user_id=user_id,
        action=action,
        description=description,
        task_id=task_id
    )
    db.session.add(activity)
    db.session.commit()

def calculate_task_points(task):
    """Рассчитать баллы за задачу в зависимости от приоритета"""
    points_map = {
        'low': 10,
        'medium': 25,
        'high': 50,
        'urgent': 100
    }
    return points_map.get(task.priority, 25)

# ========== МАРШРУТЫ (ROUTES) ==========

@app.route('/')
def index():
    """Главная страница всегда показывает форму входа"""
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password:
            flash('Все поля обязательны для заполнения', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return render_template('register.html')

        user = User(username=username, email=email, role='user')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        logger.info(f"Новый пользователь зарегистрирован: {username} ({email})")
        flash('Регистрация успешна! Войдите в систему', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Введите имя пользователя и пароль', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            logger.info(f"Пользователь вошел в систему: {username} (роль: {user.role})")
            flash(f'Добро пожаловать, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
            logger.warning(f"Неудачная попытка входа: {username}")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"Пользователь вышел из системы: {username}")
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Для администратора и зам админа показываем все задачи
    if user.is_admin_or_deputy():
        all_tasks = Task.query.order_by(Task.created_at.desc()).all()
        my_tasks = Task.query.filter_by(assignee_id=user_id).order_by(Task.created_at.desc()).all()
        assigned_tasks = Task.query.filter_by(creator_id=user_id).order_by(Task.created_at.desc()).all()
    else:
        # Для обычного пользователя показываем только его задачи
        all_tasks = Task.query.filter(
            (Task.assignee_id == user_id) | (Task.creator_id == user_id)
        ).order_by(Task.created_at.desc()).all()
        my_tasks = Task.query.filter_by(assignee_id=user_id).order_by(Task.created_at.desc()).all()
        assigned_tasks = Task.query.filter_by(creator_id=user_id).order_by(Task.created_at.desc()).all()
    
    # Статистика
    stats = {
        'total': len(all_tasks),
        'completed': len([t for t in all_tasks if t.status == 'completed']),
        'in_progress': len([t for t in all_tasks if t.status == 'in_progress']),
        'new': len([t for t in all_tasks if t.status == 'new']),
        'overdue': len([t for t in all_tasks if t.is_overdue()])
    }
    
    return render_template('dashboard.html', 
                         all_tasks=all_tasks,
                         my_tasks=my_tasks,
                         assigned_tasks=assigned_tasks,
                         stats=stats,
                         user=user)

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description', '')
        priority = request.form.get('priority', 'medium')
        assignee_id = request.form.get('assignee_id')
        deadline_str = request.form.get('deadline')
        
        if not title:
            flash('Название задачи обязательно', 'error')
            return redirect(url_for('create_task'))
        
        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except:
                pass
        
        task = Task(
            title=title,
            description=description,
            priority=priority,
            creator_id=session['user_id'],
            assignee_id=int(assignee_id) if assignee_id else None,
            deadline=deadline
        )
        db.session.add(task)
        db.session.commit()
        
        # Создаем активность
        assignee_name = task.assignee.username if task.assignee else 'Не назначен'
        create_activity(
            session['user_id'],
            'created',
            f'Создана задача "{title}" для {assignee_name}',
            task.id
        )
        
        logger.info(f"Создана задача: {title} (пользователь: {session['username']})")
        flash('Задача создана', 'success')
        return redirect(url_for('dashboard'))
    
    # GET запрос - показываем форму
    # Показываем всех пользователей, кроме текущего
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('create_task.html', users=users)

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    
    # Проверка прав: только создатель, админ или зам админа могут редактировать
    if task.creator_id != session['user_id'] and not user.is_admin_or_deputy():
        flash('У вас нет прав для редактирования этой задачи', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description', '')
        priority = request.form.get('priority', 'medium')
        status = request.form.get('status', 'new')
        assignee_id = request.form.get('assignee_id')
        deadline_str = request.form.get('deadline')
        
        if not title:
            flash('Название задачи обязательно', 'error')
            return render_template('edit_task.html', task=task, users=User.query.all())
        
        old_status = task.status
        old_assignee = task.assignee_id
        
        task.title = title
        task.description = description
        task.priority = priority
        task.status = status
        task.assignee_id = int(assignee_id) if assignee_id else None
        
        if deadline_str:
            try:
                task.deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except:
                pass
        
        # Если задача завершена, устанавливаем время завершения
        if status == 'completed' and old_status != 'completed':
            task.completed_at = datetime.utcnow()
            # Начисляем баллы исполнителю
            if task.assignee_id:
                points = calculate_task_points(task)
                assignee = User.query.get(task.assignee_id)
                assignee.add_points(points)
                create_activity(
                    task.assignee_id,
                    'completed',
                    f'Завершена задача "{title}". Начислено {points} баллов',
                    task.id
                )
        elif status != 'completed':
            task.completed_at = None
        
        task.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Создаем активность об изменении
        changes = []
        if old_status != status:
            changes.append(f'статус изменен на {status}')
        if old_assignee != task.assignee_id:
            new_assignee = task.assignee.username if task.assignee else 'Не назначен'
            changes.append(f'исполнитель изменен на {new_assignee}')
        
        if changes:
            create_activity(
                session['user_id'],
                'updated',
                f'Задача "{title}" обновлена: {", ".join(changes)}',
                task.id
            )
        
        logger.info(f"Задача обновлена: {title} (ID: {task_id})")
        flash('Задача обновлена', 'success')
        return redirect(url_for('dashboard'))
    
    # Показываем всех пользователей, кроме текущего
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('edit_task.html', task=task, users=users)

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    
    # Проверка прав: только создатель, админ или зам админа могут удалять
    if task.creator_id != session['user_id'] and not user.is_admin_or_deputy():
        flash('У вас нет прав для удаления этой задачи', 'error')
        return redirect(url_for('dashboard'))
    
    title = task.title
    db.session.delete(task)
    db.session.commit()
    
    logger.info(f"Задача удалена: {title} (ID: {task_id})")
    flash('Задача удалена', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_task_status/<int:task_id>', methods=['POST'])
@login_required
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    new_status = request.form.get('status')
    
    # Проверка прав: только исполнитель, админ или зам админа могут менять статус
    user = User.query.get(session['user_id'])
    if task.assignee_id != session['user_id'] and not user.is_admin_or_deputy():
        flash('У вас нет прав для изменения статуса этой задачи', 'error')
        return redirect(url_for('dashboard'))
    
    if new_status in ['new', 'in_progress', 'completed', 'cancelled']:
        old_status = task.status
        task.status = new_status
        
        if new_status == 'completed' and old_status != 'completed':
            task.completed_at = datetime.utcnow()
            # Начисляем баллы
            if task.assignee_id:
                points = calculate_task_points(task)
                assignee = User.query.get(task.assignee_id)
                assignee.add_points(points)
                create_activity(
                    task.assignee_id,
                    'completed',
                    f'Завершена задача "{task.title}". Начислено {points} баллов',
                    task.id
                )
        elif new_status != 'completed':
            task.completed_at = None
        
        task.updated_at = datetime.utcnow()
        db.session.commit()
        
        create_activity(
            session['user_id'],
            'status_changed',
            f'Статус задачи "{task.title}" изменен на {new_status}',
            task.id
        )
        
        flash('Статус задачи обновлен', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/reports')
@login_required
def reports():
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Получаем период для отчетов
    period = request.args.get('period', 'week')  # week, month, all
    now = datetime.utcnow()
    
    if period == 'week':
        start_date = now - timedelta(days=7)
    elif period == 'month':
        start_date = now - timedelta(days=30)
    else:
        start_date = datetime(2000, 1, 1)
    
    if user.is_admin_or_deputy():
        # Админ и зам админа видят все отчеты
        tasks = Task.query.filter(Task.created_at >= start_date).all()
        activities = Activity.query.filter(Activity.created_at >= start_date).order_by(Activity.created_at.desc()).limit(100).all()
        users_stats = User.query.all()
    else:
        # Обычный пользователь видит только свои отчеты
        tasks = Task.query.filter(
            ((Task.assignee_id == user_id) | (Task.creator_id == user_id)) &
            (Task.created_at >= start_date)
        ).all()
        activities = Activity.query.filter(
            (Activity.user_id == user_id) &
            (Activity.created_at >= start_date)
        ).order_by(Activity.created_at.desc()).limit(100).all()
        users_stats = [user]
    
    # Статистика по задачам
    task_stats = {
        'total': len(tasks),
        'completed': len([t for t in tasks if t.status == 'completed']),
        'in_progress': len([t for t in tasks if t.status == 'in_progress']),
        'new': len([t for t in tasks if t.status == 'new']),
        'cancelled': len([t for t in tasks if t.status == 'cancelled']),
        'overdue': len([t for t in tasks if t.is_overdue()])
    }
    
    # Статистика по приоритетам
    priority_stats = {
        'low': len([t for t in tasks if t.priority == 'low']),
        'medium': len([t for t in tasks if t.priority == 'medium']),
        'high': len([t for t in tasks if t.priority == 'high']),
        'urgent': len([t for t in tasks if t.priority == 'urgent'])
    }
    
    return render_template('reports.html',
                         task_stats=task_stats,
                         priority_stats=priority_stats,
                         activities=activities,
                         users_stats=users_stats,
                         period=period)

@app.route('/users')
@admin_required
def users():
    all_users = User.query.order_by(User.points.desc()).all()
    return render_template('users.html', users=all_users)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    profile_user = User.query.get_or_404(user_id)
    current_user = User.query.get(session['user_id'])
    
    # Проверка прав: пользователь может видеть только свой профиль, админ и зам админа - любой
    if profile_user.id != session['user_id'] and not current_user.is_admin_or_deputy():
        flash('У вас нет прав для просмотра этого профиля', 'error')
        return redirect(url_for('dashboard'))
    
    # Задачи пользователя
    created_tasks = Task.query.filter_by(creator_id=user_id).all()
    assigned_tasks = Task.query.filter_by(assignee_id=user_id).all()
    completed_tasks = [t for t in assigned_tasks if t.status == 'completed']
    
    # Активность
    activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(50).all()
    
    return render_template('user_profile.html',
                         profile_user=profile_user,
                         created_tasks=created_tasks,
                         assigned_tasks=assigned_tasks,
                         completed_tasks=completed_tasks,
                         activities=activities)

@app.route('/change_user_role/<int:user_id>', methods=['POST'])
@super_admin_required
def change_user_role(user_id):
    """Изменение роли пользователя - только для главного администратора"""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role in ['admin', 'deputy_admin', 'user']:
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        create_activity(
            session['user_id'],
            'role_changed',
            f'Роль пользователя {user.username} изменена с {old_role} на {new_role}',
            None
        )
        
        flash(f'Роль пользователя {user.username} изменена на {new_role}', 'success')
    else:
        flash('Недопустимая роль', 'error')
    
    return redirect(url_for('users'))

# ========== ЗАПУСК ПРИЛОЖЕНИЯ ==========
if __name__ == '__main__':
    logger.info("Запуск Flask приложения")
    app.run(debug=True)

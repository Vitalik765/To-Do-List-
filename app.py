# Импорт необходимых библиотек Flask для работы веб-приложения
from flask import Flask, render_template, request, redirect, url_for, flash, session
# Импорт SQLAlchemy для работы с базой данных
from flask_sqlalchemy import SQLAlchemy
# Импорт функций для хеширования и проверки паролей (безопасное хранение)
from werkzeug.security import generate_password_hash, check_password_hash
# Импорт datetime для работы с датами и временем
from datetime import datetime
# Импорт модуля логирования для записи событий приложения
import logging

# Настройка системы логирования
# level=logging.INFO - уровень логирования (INFO, WARNING, ERROR)
# format - формат вывода логов (дата, имя, уровень, сообщение)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        # FileHandler - запись логов в файл todo_app.log с кодировкой UTF-8
        logging.FileHandler('todo_app.log', encoding='utf-8'),
        # StreamHandler - вывод логов в консоль
        logging.StreamHandler()
    ]
)
# Создание объекта logger для записи событий в коде
logger = logging.getLogger(__name__)

# Создание экземпляра Flask приложения
app = Flask(__name__)
# SECRET_KEY - секретный ключ для шифрования сессий (важно изменить в production!)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
# SQLALCHEMY_DATABASE_URI - путь к базе данных SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
# Отключение отслеживания изменений для оптимизации производительности
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация объекта базы данных SQLAlchemy
db = SQLAlchemy(app)

# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========

# Модель User - таблица пользователей в базе данных
class User(db.Model):
    # id - первичный ключ (уникальный идентификатор пользователя)
    id = db.Column(db.Integer, primary_key=True)
    # username - имя пользователя (уникальное, обязательное, максимум 80 символов)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # email - электронная почта (уникальная, обязательная, максимум 120 символов)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # password_hash - хеш пароля (не храним пароль в открытом виде!)
    password_hash = db.Column(db.String(255), nullable=False)
    # created_at - дата и время создания аккаунта (автоматически при создании)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # todos - связь один-ко-многим с таблицей Todo (один пользователь - много задач)
    # cascade='all, delete-orphan' - при удалении пользователя удаляются все его задачи
    todos = db.relationship('Todo', backref='user', lazy=True, cascade='all, delete-orphan')

    # Метод для установки пароля (хеширует пароль перед сохранением)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Метод для проверки пароля (сравнивает введенный пароль с хешем)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Модель Todo - таблица задач в базе данных
class Todo(db.Model):
    # id - первичный ключ (уникальный идентификатор задачи)
    id = db.Column(db.Integer, primary_key=True)
    # title - название задачи (обязательное поле, максимум 200 символов)
    title = db.Column(db.String(200), nullable=False)
    # description - описание задачи (необязательное поле, текст любого размера)
    description = db.Column(db.Text, nullable=True)
    # completed - статус выполнения задачи (по умолчанию False - не выполнена)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    # created_at - дата и время создания задачи (автоматически при создании)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # updated_at - дата и время последнего обновления (автоматически обновляется при изменении)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # user_id - внешний ключ, связывающий задачу с пользователем (обязательное поле)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ========== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ==========
# Создание всех таблиц в базе данных (если их еще нет)
# app.app_context() - контекст приложения необходим для работы с БД
with app.app_context():
    db.create_all()  # Создает таблицы User и Todo
    logger.info("База данных инициализирована")

# ========== МАРШРУТЫ (ROUTES) ==========

# Главная страница (корневой маршрут '/')
@app.route('/')
def index():
    # Проверка: если пользователь уже авторизован (есть user_id в сессии)
    if 'user_id' in session:
        # Перенаправляем на панель управления
        return redirect(url_for('dashboard'))
    # Если не авторизован - перенаправляем на страницу входа
    return redirect(url_for('login'))

# Маршрут регистрации нового пользователя
# methods=['GET', 'POST'] - разрешает GET (отображение формы) и POST (отправка данных)
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Если форма была отправлена (POST запрос)
    if request.method == 'POST':
        # Получаем данные из формы регистрации
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # ========== ВАЛИДАЦИЯ ДАННЫХ ==========
        # Проверка: все ли обязательные поля заполнены
        if not username or not email or not password:
            flash('Все поля обязательны для заполнения', 'error')
            logger.warning(f"Попытка регистрации с пустыми полями")
            return render_template('register.html')

        # Проверка: совпадают ли пароль и подтверждение пароля
        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            logger.warning(f"Попытка регистрации: пароли не совпадают для {username}")
            return render_template('register.html')

        # Проверка: существует ли уже пользователь с таким именем
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            logger.warning(f"Попытка регистрации существующего пользователя: {username}")
            return render_template('register.html')

        # Проверка: существует ли уже пользователь с таким email
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            logger.warning(f"Попытка регистрации существующего email: {email}")
            return render_template('register.html')

        # ========== СОЗДАНИЕ НОВОГО ПОЛЬЗОВАТЕЛЯ ==========
        # Создаем объект пользователя
        user = User(username=username, email=email)
        # Хешируем пароль перед сохранением (безопасность!)
        user.set_password(password)
        # Добавляем пользователя в сессию базы данных
        db.session.add(user)
        # Сохраняем изменения в базе данных
        db.session.commit()
        # Логируем успешную регистрацию
        logger.info(f"Новый пользователь зарегистрирован: {username} ({email})")
        # Показываем сообщение об успехе
        flash('Регистрация успешна! Войдите в систему', 'success')
        # Перенаправляем на страницу входа
        return redirect(url_for('login'))

    # Если GET запрос - просто показываем форму регистрации
    return render_template('register.html')

# Маршрут входа в систему (авторизация)
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Если форма была отправлена (POST запрос)
    if request.method == 'POST':
        # Получаем данные из формы входа
        username = request.form.get('username')
        password = request.form.get('password')

        # Проверка: заполнены ли поля
        if not username or not password:
            flash('Введите имя пользователя и пароль', 'error')
            return render_template('login.html')

        # Ищем пользователя в базе данных по имени
        user = User.query.filter_by(username=username).first()

        # Проверка: существует ли пользователь и правильный ли пароль
        if user and user.check_password(password):
            # Сохраняем ID и имя пользователя в сессии (для отслеживания авторизованного пользователя)
            session['user_id'] = user.id
            session['username'] = user.username
            # Логируем успешный вход
            logger.info(f"Пользователь вошел в систему: {username}")
            flash(f'Добро пожаловать, {username}!', 'success')
            # Перенаправляем на панель управления
            return redirect(url_for('dashboard'))
        else:
            # Если пользователь не найден или пароль неверный
            flash('Неверное имя пользователя или пароль', 'error')
            logger.warning(f"Неудачная попытка входа: {username}")
            return render_template('login.html')

    # Если GET запрос - просто показываем форму входа
    return render_template('login.html')

# Маршрут выхода из системы
@app.route('/logout')
def logout():
    # Получаем имя пользователя из сессии (для логирования)
    username = session.get('username', 'Unknown')
    # Очищаем всю сессию (удаляем данные авторизованного пользователя)
    session.clear()
    # Логируем выход
    logger.info(f"Пользователь вышел из системы: {username}")
    flash('Вы вышли из системы', 'info')
    # Перенаправляем на страницу входа
    return redirect(url_for('login'))

# Маршрут панели управления (главная страница после входа)
@app.route('/dashboard')
def dashboard():
    # Проверка авторизации: если пользователь не вошел в систему
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))

    # Получаем ID текущего пользователя из сессии
    user_id = session['user_id']
    # Получаем все задачи текущего пользователя из базы данных
    # filter_by(user_id=user_id) - фильтруем только задачи этого пользователя
    # order_by(Todo.created_at.desc()) - сортируем по дате создания (новые сверху)
    # .all() - получаем все результаты
    todos = Todo.query.filter_by(user_id=user_id).order_by(Todo.created_at.desc()).all()
    # Отображаем шаблон dashboard.html и передаем список задач
    return render_template('dashboard.html', todos=todos)

# Маршрут добавления новой задачи (только POST запрос)
@app.route('/add_todo', methods=['POST'])
def add_todo():
    # Проверка авторизации
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))

    # Получаем данные из формы добавления задачи
    title = request.form.get('title')
    description = request.form.get('description', '')  # Описание необязательное

    # Валидация: название задачи обязательно
    if not title:
        flash('Название задачи обязательно', 'error')
        return redirect(url_for('dashboard'))

    # Создаем новый объект задачи
    todo = Todo(
        title=title,
        description=description,
        user_id=session['user_id']  # Связываем задачу с текущим пользователем
    )
    # Добавляем задачу в сессию базы данных
    db.session.add(todo)
    # Сохраняем изменения в базе данных
    db.session.commit()
    # Логируем добавление задачи
    logger.info(f"Добавлена новая задача: {title} (пользователь: {session['username']})")
    flash('Задача добавлена', 'success')
    # Перенаправляем обратно на панель управления
    return redirect(url_for('dashboard'))

# Маршрут переключения статуса задачи (выполнена/не выполнена)
# <int:todo_id> - параметр маршрута (ID задачи из URL)
@app.route('/toggle_todo/<int:todo_id>')
def toggle_todo(todo_id):
    # Проверка авторизации
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))

    # Получаем задачу из базы данных по ID (404 если не найдена)
    todo = Todo.query.get_or_404(todo_id)
    # Проверка прав доступа: задача должна принадлежать текущему пользователю
    if todo.user_id != session['user_id']:
        flash('У вас нет доступа к этой задаче', 'error')
        logger.warning(f"Попытка доступа к чужой задаче: {todo_id} (пользователь: {session['username']})")
        return redirect(url_for('dashboard'))

    # Переключаем статус задачи (если была выполнена - делаем невыполненной и наоборот)
    todo.completed = not todo.completed
    # Обновляем время последнего изменения
    todo.updated_at = datetime.utcnow()
    # Сохраняем изменения в базе данных
    db.session.commit()
    # Определяем статус для логирования
    status = 'выполнена' if todo.completed else 'не выполнена'
    logger.info(f"Задача {todo_id} помечена как {status} (пользователь: {session['username']})")
    # Перенаправляем обратно на панель управления
    return redirect(url_for('dashboard'))

# Маршрут удаления задачи
# <int:todo_id> - параметр маршрута (ID задачи из URL)
@app.route('/delete_todo/<int:todo_id>')
def delete_todo(todo_id):
    # Проверка авторизации
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))

    # Получаем задачу из базы данных по ID (404 если не найдена)
    todo = Todo.query.get_or_404(todo_id)
    # Проверка прав доступа: задача должна принадлежать текущему пользователю
    if todo.user_id != session['user_id']:
        flash('У вас нет доступа к этой задаче', 'error')
        logger.warning(f"Попытка удаления чужой задачи: {todo_id} (пользователь: {session['username']})")
        return redirect(url_for('dashboard'))

    # Сохраняем название задачи для логирования (перед удалением)
    title = todo.title
    # Удаляем задачу из базы данных
    db.session.delete(todo)
    # Сохраняем изменения в базе данных
    db.session.commit()
    # Логируем удаление задачи
    logger.info(f"Задача удалена: {title} (ID: {todo_id}, пользователь: {session['username']})")
    flash('Задача удалена', 'success')
    # Перенаправляем обратно на панель управления
    return redirect(url_for('dashboard'))

# Маршрут редактирования задачи
# <int:todo_id> - параметр маршрута (ID задачи из URL)
# methods=['GET', 'POST'] - GET для отображения формы, POST для сохранения изменений
@app.route('/edit_todo/<int:todo_id>', methods=['GET', 'POST'])
def edit_todo(todo_id):
    # Проверка авторизации
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))

    # Получаем задачу из базы данных по ID (404 если не найдена)
    todo = Todo.query.get_or_404(todo_id)
    # Проверка прав доступа: задача должна принадлежать текущему пользователю
    if todo.user_id != session['user_id']:
        flash('У вас нет доступа к этой задаче', 'error')
        logger.warning(f"Попытка редактирования чужой задачи: {todo_id} (пользователь: {session['username']})")
        return redirect(url_for('dashboard'))

    # Если форма была отправлена (POST запрос) - сохраняем изменения
    if request.method == 'POST':
        # Получаем обновленные данные из формы
        title = request.form.get('title')
        description = request.form.get('description', '')

        # Валидация: название задачи обязательно
        if not title:
            flash('Название задачи обязательно', 'error')
            return render_template('edit_todo.html', todo=todo)

        # Обновляем данные задачи
        todo.title = title
        todo.description = description
        # Обновляем время последнего изменения
        todo.updated_at = datetime.utcnow()
        # Сохраняем изменения в базе данных
        db.session.commit()
        # Логируем редактирование задачи
        logger.info(f"Задача отредактирована: {title} (ID: {todo_id}, пользователь: {session['username']})")
        flash('Задача обновлена', 'success')
        # Перенаправляем обратно на панель управления
        return redirect(url_for('dashboard'))

    # Если GET запрос - показываем форму редактирования с текущими данными задачи
    return render_template('edit_todo.html', todo=todo)

# ========== ЗАПУСК ПРИЛОЖЕНИЯ ==========
# Этот блок выполняется только при прямом запуске файла (не при импорте)
if __name__ == '__main__':
    # Логируем запуск приложения
    logger.info("Запуск Flask приложения")
    # Запускаем Flask сервер
    # debug=True - включает режим отладки (автоперезагрузка при изменениях, подробные ошибки)
    app.run(debug=True)


import flet as ft
import sqlite3
import bcrypt
import random
import string

def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY,
                      username TEXT UNIQUE,
                      password TEXT)''')
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return True, "Registration successful!"
    except sqlite3.IntegrityError:
        return False, "Username already exists!"
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode(), user[0].encode()):
        return True, "Login successful!"
    return False, "Invalid username or password."

def change_password(username, old_password, new_password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(old_password.encode(), user[0].encode()):
        hashed_new_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_pw, username))
        conn.commit()
        conn.close()
        return True, "Password changed successfully!"
    conn.close()
    return False, "Invalid username or old password."

def generate_captcha():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def main(page: ft.Page):
    page.title = "Auth App"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 381
    page.window_height = 674
    
    languages = {"en": "English", "ru": "Русский"}
    lang = "en"
    
    def update_language(e):
        nonlocal lang
        lang = e.control.value
        refresh_ui()
    
    def refresh_ui():
        login_username.label = "Username" if lang == "en" else "Имя пользователя"
        login_password.label = "Password" if lang == "en" else "Пароль"
        login_button.text = "Login" if lang == "en" else "Войти"
        register_redirect.text = "Don't have an account? Register" if lang == "en" else "Нет аккаунта? Зарегистрируйтесь"
        forgot_password_button.text = "Forgot Password?" if lang == "en" else "Забыли пароль?"
        reg_username.label = "Username" if lang == "en" else "Имя пользователя"
        reg_password.label = "Password" if lang == "en" else "Пароль"
        reg_captcha.label = "Enter Captcha" if lang == "en" else "Введите капчу"
        captcha_label.value = f"Captcha: {captcha_code}"
        refresh_button.text = "Refresh Captcha" if lang == "en" else "Обновить капчу"
        register_button.text = "Register" if lang == "en" else "Зарегистрироваться"
        login_redirect.text = "Already have an account? Login" if lang == "en" else "Уже есть аккаунт? Войти"
        change_password_username.label = "Username" if lang == "en" else "Имя пользователя"
        change_password_old.label = "Old Password" if lang == "en" else "Старый пароль"
        change_password_new.label = "New Password" if lang == "en" else "Новый пароль"
        change_password_button.text = "Change Password" if lang == "en" else "Сменить пароль"
        change_password_redirect.text = "Back to Login" if lang == "en" else "Вернуться к входу"
        page.update()
    
    captcha_code = generate_captcha()
    
    def refresh_captcha(_):
        nonlocal captcha_code
        captcha_code = generate_captcha()
        captcha_label.value = f"Captcha: {captcha_code}"
        captcha_label.update()
    
    def switch_to_register(_):
        page.clean()
        page.add(register_view)
        page.update()
    
    def switch_to_login(_):
        page.clean()
        page.add(login_view)
        page.update()
    
    def switch_to_change_password(_):
        page.clean()
        page.add(change_password_view)
        page.update()
    
    def handle_register(_):
        if not reg_username.value or not reg_password.value or not reg_captcha.value:
            reg_msg.value = "Fields cannot be empty!" if lang == "en" else "Поля не могут быть пустыми!"
            reg_msg.color = "red"
        elif reg_captcha.value != captcha_code:
            reg_msg.value = "Invalid captcha!" if lang == "en" else "Неверная капча!"
            reg_msg.color = "red"
        else:
            success, msg = register_user(reg_username.value, reg_password.value)
            reg_msg.value = msg
            reg_msg.color = "green" if success else "red"
        reg_msg.update()
    
    def handle_login(_):
        if not login_username.value or not login_password.value:
            login_msg.value = "Fields cannot be empty!" if lang == "en" else "Поля не могут быть пустыми!"
            login_msg.color = "red"
        else:
            success, msg = authenticate_user(login_username.value, login_password.value)
            login_msg.value = msg
            login_msg.color = "green" if success else "red"
        login_msg.update()
    
    def handle_change_password(_):
        if not change_password_username.value or not change_password_old.value or not change_password_new.value:
            change_password_msg.value = "Fields cannot be empty!" if lang == "en" else "Поля не могут быть пустыми!"
            change_password_msg.color = "red"
        else:
            success, msg = change_password(change_password_username.value, change_password_old.value, change_password_new.value)
            change_password_msg.value = msg
            change_password_msg.color = "green" if success else "red"
        change_password_msg.update()
    
    language_dropdown = ft.Dropdown(label="Lang", width=80, options=[ft.dropdown.Option("en", "en"), ft.dropdown.Option("ru", "ru")], on_change=update_language)
    language_button = ft.Row([language_dropdown], alignment=ft.MainAxisAlignment.END)
    
    # Login UI
    login_username = ft.TextField(label="Username")
    login_password = ft.TextField(label="Password", password=True)
    login_msg = ft.Text()
    login_button = ft.ElevatedButton("Login", on_click=handle_login)
    register_redirect = ft.TextButton("Don't have an account? Register", on_click=switch_to_register, opacity=0.7)
    forgot_password_button = ft.TextButton("Forgot Password?", on_click=switch_to_change_password, opacity=0.7)
    login_view = ft.Column([language_button, login_username, login_password, login_button, login_msg, register_redirect, forgot_password_button],
                           alignment=ft.MainAxisAlignment.CENTER)
    
    # Register UI
    reg_username = ft.TextField(label="Username")
    reg_password = ft.TextField(label="Password", password=True)
    reg_captcha = ft.TextField(label="Enter Captcha")
    captcha_label = ft.Text(f"Captcha: {captcha_code}")
    refresh_button = ft.TextButton("Refresh Captcha", on_click=refresh_captcha)
    reg_msg = ft.Text()
    register_button = ft.ElevatedButton("Register", on_click=handle_register)
    login_redirect = ft.TextButton("Already have an account? Login", on_click=switch_to_login, opacity=0.7)
    register_view = ft.Column([language_button, reg_username, reg_password, captcha_label, reg_captcha, refresh_button, register_button, reg_msg, login_redirect],
                              alignment=ft.MainAxisAlignment.CENTER)
    
    # Change Password UI
    change_password_username = ft.TextField(label="Username")
    change_password_old = ft.TextField(label="Old Password", password=True)
    change_password_new = ft.TextField(label="New Password", password=True)
    change_password_msg = ft.Text()
    change_password_button = ft.ElevatedButton("Change Password", on_click=handle_change_password)
    change_password_redirect = ft.TextButton("Back to Login", on_click=switch_to_login, opacity=0.7)
    change_password_view = ft.Column([language_button, change_password_username, change_password_old, change_password_new, change_password_button, change_password_msg, change_password_redirect],
                                     alignment=ft.MainAxisAlignment.CENTER)
    
    page.add(login_view)

if __name__ == "__main__":
    init_db()
    ft.app(target=main)
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.markup import render

import util
import pandas as pd
import logging
import mysql.connector
import os
import base64



# Initialize Flask app
app = Flask(__name__)
app.secret_key = '7a0f4c08c43d5bb2f4a97d5756fc5e26e31c457db080'


# Database connection setup
# def get_db_connection():
#     return mysql.connector.connect(
#         host='localhost',
#         user='root',
#         password='',
#         database='another'
#     )

def get_db_connection():
    return mysql.connector.connect(
        host='M4XW311.mysql.pythonanywhere-services.com',
        user='M4XW311',
        password='L3gendary1864',
        database="M4XW311$default"
    )



# Set up logging for better error tracking
logging.basicConfig(level=logging.DEBUG)


# Password hashing using cryptography (PBKDF2)
# Password hashing using cryptography (PBKDF2)
def hash_password(password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()


# Verify password with the stored hash
def verify_password(stored_password: str, password: str, salt: bytes) -> bool:
    # Log hashed attempts to ensure the verification works correctly
    hashed_attempt = hash_password(password, salt)
    app.logger.debug(f"Stored hashed password: {stored_password}")
    app.logger.debug(f"Hashed password attempt: {hashed_attempt}")
    return stored_password == hashed_attempt




@app.route('/')
def index():
    return render_template('index.html')


@app.route('/news')
def news():
    # Fetch news articles and comments
    conn = get_db_connection()
    cursor = conn.cursor()
    # cursor.execute("SELECT * FROM articles")
    # articles = cursor.fetchall()

    # cursor.execute("SELECT * FROM comments")
    # comments = cursor.fetchall()

    conn.close()

    # return render_template('index.html',
                        #   articles=articles,
                        #   comments=comments,
                        #   logged_in=session.get('logged_in'),
                        #   username=session.get('username'))
    return render_template('news.html',
                      logged_in=session.get('logged_in'),
                      username=session.get('username'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Fetch input from the form
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']  # Ensure this is the plain text password

        # Generate a salt and hash the password
        salt = os.urandom(16)
        hashed_password = hash_password(password, salt)

        # Debugging: Log values before inserting into the database
        app.logger.debug(f"Username: {username}")
        app.logger.debug(f"Email: {email}")
        app.logger.debug(f"Password: {password}")
        app.logger.debug(f"Hashed Password: {hashed_password}")
        app.logger.debug(f"Salt: {base64.urlsafe_b64encode(salt).decode()}")

        # Default role_id for new users (1 for regular users)
        role_id = 11

        # Insert into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO nkani_users (username, password, email, salt, role_id) VALUES (%s, %s, %s, %s, %s)",
            (username, hashed_password, email, base64.urlsafe_b64encode(salt).decode(), role_id)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM nkani_users WHERE username = %s", (username,))
        user = cursor.fetchone()

        print(user)

        if user:
            stored_password = user[3]  # Hash stored in the third column
            salt = base64.urlsafe_b64decode(user[7])  # Retrieve the salt
            if verify_password(stored_password, password, salt):
                # Fetch role name from user_roles table
                cursor.execute("SELECT role_name FROM nkani_user_roles WHERE id = %s", (user[4],))  # user[4] is the role_id
                role = cursor.fetchone()
                role_name = role[0] if role else 'Unknown'

                session['user_id'] = user[0]  # Store user_id in session
                session['username'] = user[1]  # Store username in session
                session['role'] = role_name  # Store role in session
                session['logged_in'] = True  # Mark user as logged in

                return redirect(url_for('news'))

        return "Invalid username or password"

    return render_template('login.html')


@app.route('/logout')
def logout():
    # Clear the session data
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('logged_in', None)

    # Redirect to the login page or homepage
    return redirect(url_for('login'))


# @app.route('/comment/<article_id>', methods=['POST'])
# def comment(article_id):
#     if 'user_id' not in session:
#         return jsonify({'success': False, 'message': 'You must be logged in to comment.'}), 400
#
#     user_id = session['user_id']
#
#     # Use request.json.get() to extract the comment when sending JSON data
#     comment_text = request.json.get('comment')
#
#     if not comment_text:
#         return jsonify({'success': False, 'message': 'Comment cannot be empty.'}), 400
#
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("INSERT INTO comments (user_id, article_id, comment) VALUES (%s, %s, %s)",
#                        (user_id, article_id, comment_text))
#         conn.commit()
#         conn.close()
#         return jsonify({'success': True, 'message': 'Comment posted successfully.'})
#     except Exception as e:
#         return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
#
#
# # Delete comment functionality
# @app.route('/delete_comment/<comment_id>', methods=['POST'])
# def delete_comment(comment_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("DELETE FROM comments WHERE id = ? AND user_id = ?", (comment_id, session['user_id']))
#     conn.commit()
#     conn.close()
#
#     return jsonify({'success': True, 'message': 'Comment deleted successfully.'}), 200
#
#
# @app.route('/get_comments/<article_id>', methods=['GET'])
# def get_comments(article_id):
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("""
#             SELECT comments.id, users.username, comments.comment
#             FROM comments
#             JOIN users ON comments.user_id = users.id
#             WHERE comments.article_id = %s
#             """, (article_id,))
#         comments = cursor.fetchall()
#         conn.close()
#
#         # Convert the results to a list of dictionaries
#         comment_list = [{'id': comment[0], 'username': comment[1], 'commentText': comment[2]} for comment in comments]
#
#         return jsonify({'comments': comment_list})
#     except Exception as e:
#         return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/fetch_news', methods=['POST'])
def fetch_news():
    try:
        print(jsonify({"message": "News fetched successfully"}))
        # Get data from the frontend (categories, country)
        data = request.get_json()
        print(data)

        # Validate input
        if not data or 'categories' not in data or 'country' not in data:
            return jsonify({'error': 'Categories and country are required'}), 400

        categories = data['categories']
        country = data['country']

        if not categories or not country:
            return jsonify({'error': 'Invalid categories or country data'}), 400

        # Fetch and process the news
        df = util.scrape_news(country, categories)

        if df.empty or 'title' not in df.columns:
            return jsonify({'error': 'No news found for the provided categories and country'}), 404

        # Apply sentiment analysis and sector impact (handling missing data safely)
        df['Sentiment'] = df['title'].apply(lambda title: util.analyze_sentiment(title) if title else 'Neutral')
        df['Sector Impact'] = df['title'].apply(lambda title: util.analyze_sector_impact(title) if title else 'Low')

        # Prepare and send the results
        articles = []
        for _, row in df.iterrows():
            article = {
                'title': row['title'],
                'publishedAt': row['publishedAt'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(row['publishedAt'],
                                                                                              pd.Timestamp) else row[
                    'publishedAt'],
                'sentiment': row['Sentiment'],
                'sectorImpact': row['Sector Impact'],
                'link': row['link'],
                'image': row.get('image', '')
            }
            articles.append(article)

        return jsonify({'articles': articles}), 200

    except KeyError as e:
        # Catch missing field errors (like 'categories' or 'country')
        app.logger.error(f"KeyError: Missing {str(e)}")
        return jsonify({'error': f'Missing required field: {str(e)}'}), 400

    except Exception as e:
        # Log unexpected errors and provide a generic error message
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred, please try again later'}), 500

# def create_default_roles():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("SELECT COUNT(*) FROM user_roles WHERE role_name IN ('admin', 'regular_user')")
#     result = cursor.fetchone()
#     if result[0] == 0:
#         cursor.execute("INSERT INTO user_roles (role_name) VALUES ('admin')")
#         cursor.execute("INSERT INTO user_roles (role_name) VALUES ('regular_user')")
#         conn.commit()
#         conn.close()
#
# create_default_roles()
if __name__ == '__main__':
    app.run(debug=True)

import urllib

from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.markup import render
from urllib.parse import unquote

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


def get_article_id_from_link(article_link):
    if not article_link:
        app.logger.error("Received empty article link.")
        raise ValueError("Article link cannot be empty.")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM articles WHERE link = %s", (article_link,))
        article_ids = cursor.fetchall()

        if not article_ids:
            app.logger.warning(f"No articles found for link: {article_link}")

        app.logger.debug(f"Found article IDs: {article_ids}")  # Log article IDs

        return [article_id[0] for article_id in article_ids]

    except Exception as e:
        app.logger.error(f"Error in get_article_id_from_link: {str(e)}")
        raise ValueError(f"Error retrieving article ID: {str(e)}")

    finally:
        if conn:
            conn.close()


#-------BEGINNING OF PAGE ROUTES
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/news')
def news():
    # Fetch news articles and comments
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM articles")
    articles = cursor.fetchall()

    cursor.execute("SELECT * FROM comments")
    comments = cursor.fetchall()
    conn.close()

    return render_template('news.html',
                           articles=articles,
                           comments=comments,
                           user_id=session.get('user_id'),
                           logged_in=session.get('logged_in'),
                           username=session.get('username'))


@app.route('/admin')
def admin():
    # Fetch news articles and comments
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM articles")
    articles = cursor.fetchall()

    cursor.execute("SELECT * FROM comments")
    comments = cursor.fetchall()
    conn.close()

    return render_template('admin.html',
                           articles=articles,
                           comments=comments,
                           user_id=session.get('user_id'),
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
                cursor.execute("SELECT role_name FROM nkani_user_roles WHERE id = %s", (user[4],))
                role = cursor.fetchone()
                role_name = role[0] if role else 'Unknown'

                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = role_name
                session['logged_in'] = True

                return redirect(url_for('news'))

        return "Invalid username or password"

    return render_template('login.html')

#---------END OF PAGE ROUTES

@app.route('/logout')
def logout():
    # Clear the session data
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('logged_in', None)

    # Redirect to the login page or homepage
    return redirect(url_for('login'))

# INSERTING A COMMENT IN THE DATABASE
@app.route('/comment', methods=['POST'])
def comment():
    # Extract data from the JSON body of the request
    data = request.get_json()
    print(data)

    if not data:
        return jsonify({'success': False, 'message': 'No data provided.'}), 400

    article_link = data.get('article_id')  # Get article ID from the body
    comment_text = data.get('comment')   # Get the comment text from the body

    if not article_link or not comment_text:
        return jsonify({'success': False, 'message': 'Article ID and Comment are required.'}), 400

    # Check if the user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You must be logged in to comment.'}), 400

    user_id = session['user_id']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
                    INSERT INTO articles (title, content, link) 
                    VALUES ('Default Title', 'Default Content', %s)
        """, (article_link,))

        article_id = cursor.lastrowid  # Get the last inserted ID, which is the article ID

        cursor.execute("""
                    INSERT INTO comments (user_id, article_id, comment_text) 
                    VALUES (%s, %s, %s)
                """, (user_id, article_id, comment_text))

        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Comment posted successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


# UPDATING AN INSERTED COMMENT
@app.route('/comment', methods=['PUT'])
def update_comment():
    # Extract data from the JSON body of the request
    data = request.get_json()
    print(data)

    if not data:
        return jsonify({'success': False, 'message': 'No data provided.'}), 400

    comment_id = data.get('comment_id')  # Get the comment ID from the body
    updated_text = data.get('comment')  # Get the updated comment text from the body

    if not comment_id or not updated_text:
        return jsonify({'success': False, 'message': 'Comment ID and updated text are required.'}), 400

    # Check if the user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You must be logged in to update a comment.'}), 400

    user_id = session['user_id']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the comment exists and belongs to the logged-in user
        cursor.execute("""
            SELECT id FROM comments WHERE id = %s AND user_id = %s
        """, (comment_id, user_id))
        result = cursor.fetchone()

        if not result:
            return jsonify({'success': False, 'message': 'Comment not found or you do not have permission to update it.'}), 403

        # Update the comment text
        cursor.execute("""
            UPDATE comments SET comment_text = %s WHERE id = %s
        """, (updated_text, comment_id))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Comment updated successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500



# DELETING A COMMENT FROM THE DATABASE
@app.route('/delete_comment', methods=['POST'])
def delete_comment():
    # Extract data from the JSON body of the request
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided.'}), 400

    comment_id = data.get('comment_id')  # Get comment ID from the body

    if not comment_id:
        return jsonify({'success': False, 'message': 'Comment ID is required.'}), 400

    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM comments WHERE id = %s AND user_id = %s", (comment_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Comment deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


# GETTING COMMENTS FROM THE DATABASE
@app.route('/get_comments', methods=['POST'])
def get_comments():
    data = request.get_json(force=True)
    article_link = data.get('article_id')

    if not article_link:
        return jsonify({'success': False, 'message': 'Article ID is required.'}), 400

    try:
        # Get the article IDs for the given link
        article_ids = get_article_id_from_link(article_link)

        # If no article IDs are found, return an error
        if not article_ids:
            return jsonify({'success': False, 'message': 'No articles found for the given link.'}), 404

        conn = get_db_connection()
        cursor = conn.cursor()

        # Modify query to handle multiple article IDs
        query = """
            SELECT comments.id, nkani_users.username, comments.comment_text, comments.user_id
            FROM comments
            JOIN nkani_users ON comments.user_id = nkani_users.id
            WHERE comments.article_id IN (%s)
        """ % ','.join(['%s'] * len(article_ids))  # Safely handle multiple article_ids

        cursor.execute(query, tuple(article_ids))
        comments = cursor.fetchall()
        conn.close()

        # Process the comments into a list of dictionaries
        comment_list = [{'id': comment[0], 'username': comment[1], 'commentText': comment[2], 'user_id': comment[3]} for comment in comments]

        return jsonify({'comments': comment_list})

    except Exception as e:
        app.logger.error(f"Error in get_comments: {str(e)}")  # Log the actual error
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


#-----------ADMIN ROUTE CONTROLS FOR CRUD FUNCTIONALITIES-------------
# VIEWING ALL USERS
@app.route('/admin/users', methods=['GET'])
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email FROM nkani_users")
        users = cursor.fetchall()
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# ADDING USER INFO
@app.route('/admin/users', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')  # Assume the frontend hashes the password

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO nkani_users (username, email, password) VALUES (%s, %s, %s)
        """, (username, email, password))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User added successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# EDITING USER INFO
@app.route('/admin/users/<int:user_id>', methods=['PUT'])
def edit_user(user_id):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET username = %s, email = %s WHERE id = %s
        """, (username, email, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User updated successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# DELETING USER INFO
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User deleted successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# VIEWING ALL COMMENTS
@app.route('/admin/comments', methods=['GET'])
def admin_get_comments():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT comments.id, comments.comment_text, nkani_users.username, articles.link
            FROM comments
            JOIN users ON comments.user_id = nkani_users.id
            JOIN articles ON comments.article_id = articles.id
        """)
        comments = cursor.fetchall()
        conn.close()
        return jsonify(comments)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# DELETING COMMENTS
@app.route('/admin/comments/<int:comment_id>', methods=['DELETE'])
def admin_delete_comment(comment_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Comment deleted successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


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

if __name__ == '__main__':
    app.run(debug=True)

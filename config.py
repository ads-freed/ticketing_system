import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///ticketing.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(BASEDIR, 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'zip', 'docx', 'txt', 'xlsx'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    WTF_CSRF_ENABLED = True

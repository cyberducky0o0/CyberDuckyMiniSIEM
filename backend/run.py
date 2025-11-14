"""
Application entry point
"""
import os
from dotenv import load_dotenv
from app import create_app
from app.extensions import db

# Load environment variables
load_dotenv()

# Create app
app = create_app(os.getenv('FLASK_ENV', 'development'))

@app.cli.command()
def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        print("Database initialized!")

@app.cli.command()
def drop_db():
    """Drop all database tables"""
    with app.app_context():
        db.drop_all()
        print("Database dropped!")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


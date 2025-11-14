"""
Flask application factory
"""
import os
import logging
from flask import Flask
from app.extensions import db, jwt, cors, migrate
from app.config import config

def create_app(config_name=None):
    """
    Create and configure Flask application
    
    Args:
        config_name: Configuration name (development, production)
        
    Returns:
        Configured Flask app
    """
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    migrate.init_app(app, db)
    
    # Register blueprints
    from app.controllers.auth_controller import auth_bp
    from app.controllers.upload_controller import upload_bp
    from app.controllers.analysis_controller import analysis_bp
    from app.controllers.anomaly_controller import anomaly_bp
    from app.controllers.log_entry_controller import log_entry_bp
    from app.controllers.visualization_controller import visualization_bp
    from app.controllers.llm_controller import llm_bp
    from app.controllers.dashboard_controller import dashboard_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(upload_bp, url_prefix='/api/upload')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(anomaly_bp, url_prefix='/api/anomalies')
    app.register_blueprint(log_entry_bp, url_prefix='/api/log-entries')
    app.register_blueprint(visualization_bp, url_prefix='/api/visualization')
    app.register_blueprint(llm_bp, url_prefix='/api/llm')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    
    # Error handlers
    from app.middleware.error_handler import register_error_handlers
    register_error_handlers(app)
    
    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy'}, 200
    
    @app.route('/')
    def index():
        return {
            'name': 'CyberDucky Mini SIEM API',
            'version': '1.0.0',
            'status': 'running'
        }, 200
    
    return app


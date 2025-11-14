"""
Error handler middleware
"""
from flask import jsonify
from werkzeug.exceptions import HTTPException
import logging

logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """Register error handlers for the app"""
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Handle HTTP exceptions"""
        return jsonify({
            'error': e.description,
            'code': e.code
        }), e.code
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle general exceptions"""
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        return jsonify({
            'error': 'Internal server error'
        }), 500
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 errors"""
        return jsonify({
            'error': 'Resource not found'
        }), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        """Handle 405 errors"""
        return jsonify({
            'error': 'Method not allowed'
        }), 405


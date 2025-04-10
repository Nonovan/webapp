from flask import Blueprint, current_app, request
from extensions import metrics
from .routes import *

auth_bp = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    template_folder='templates'
)

# Auth-specific error handlers
@auth_bp.app_errorhandler(401)
def unauthorized_error(error):
    current_app.logger.warning(f'Unauthorized access: {request.url}')
    metrics.increment('auth_unauthorized_total')
    return {'error': 'Unauthorized access'}, 401

@auth_bp.app_errorhandler(403)
def forbidden_error(error):
    current_app.logger.warning(f'Forbidden access: {request.url}')
    metrics.increment('auth_forbidden_total')
    return {'error': 'Forbidden access'}, 403

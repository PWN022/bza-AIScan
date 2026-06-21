HIGH_VALUE_PATHS = {
    'admin': ['/admin', '/admin/login', '/manager/html', '/actuator', '/actuator/health', '/swagger-ui.html', '/swagger-ui'],
    'backup': ['/.git/config', '/.svn/entries', '/wwwroot.zip', '/backup.sql', '/.index.php.swp', '/.env'],
    'config': ['/config.php', '/database.yml', '/robots.txt', '/crossdomain.xml', '/WEB-INF/web.xml', '/application.yml'],
    'key': ['/js/encrypt.js', '/js/aes.js', '/config/jwt.yaml', '/server.key', '/id_rsa'],
}

STATUS_CODE_STRATEGY = {
    200: {'desc': 'Accessible', 'action': 'Directly analyze content'},
    301: {'desc': 'Redirect', 'action': 'Check redirect target and response body for sensitive data'},
    302: {'desc': 'Redirect', 'action': 'Check redirect target and response body for sensitive data'},
    401: {'desc': 'Unauthorized', 'action': 'Add to brute force target list'},
    403: {'desc': 'Forbidden', 'action': 'Try bypass techniques or deeper directory scan'},
    500: {'desc': 'Server Error', 'action': 'Add to parameter fuzzing target list'},
}

HIGH_RISK_KEYWORDS = ['admin', 'login', 'backup', '.git', '.env', 'config', 'jwt', 'key', 'secret', 'token', 'password']
MEDIUM_RISK_KEYWORDS = ['api', 'swagger', 'actuator', 'upload', 'debug', 'test', 'dev']

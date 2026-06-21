from setuptools import setup, find_packages

setup(
    name='pathfinder',
    version='0.1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'pathfinder=scripts.auto_scan:auto_scan_cli',
        ],
    },
    install_requires=[
        'requests',
        'beautifulsoup4',
        'pandas',
        'scikit-learn',
        'xgboost',
        'joblib',
        'lxml',
        'flask',
        'python-dotenv',
        'openai',
    ],
)

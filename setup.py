from setuptools import setup, find_packages

setup(
    name='DirAI-BzA',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'dirai=scripts.auto_scan:auto_scan_cli',
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

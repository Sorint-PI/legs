# LEGS (LDAP Extended Giga Sync)

Sync LDAP passwords across different Identity Providers by intercepting password modify operations.

## Deployment
Clone the project:
```
git clone 'https://github.com/Sorint-PI/legs'
```
Create a python virtual environment:
```
cd legs
python -m venv venv
```
Install the required dependencies:
```
venv/bin/pip install -r requirements.txt
```
Copy the default template:
```
cp config-template.py legs/config.py
```
Make sure the INTERCEPT_TO_STDOUT_DEBUG_MODE variable is set to True:
```
INTERCEPT_TO_STDOUT_DEBUG_MODE = True
```
Launch the script to check if passwords are detected:
```
venv/bin/python legs/main.py
```

## Running tests
[See tests/README.md](tests/README.md)

# Running tests

Create a venv environment in the root of the project (it MUST be in the upmost directory):
```
python -m venv venv
```
Install the needed requirements in the venv as per the installation guide:
```
pip install -r requirements-dev.txt
```
Enter the tests directory and launch the default compose (currently only works with podman due to difficulties running FreeIPA in Docker):
```
cd tests
./rebuild-and-restart-tests.sh
```


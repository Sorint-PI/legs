# Running tests

Create a venv environment in the root of the project (it MUST be in the upmost directory):
```
python -m venv venv
```
Install the development requirements in the venv as well as the normal requirements:
```
venv/bin/pip install -r requirements-dev.txt
```
```
venv/bin/pip install -r requirements.txt
```
Enter the tests directory and launch the default compose (currently only works with podman due to difficulties running FreeIPA in Docker):
```
cd tests
./rebuild-and-restart-tests.sh
```
Go back to the root of the project:
```
cd ..
```
Copy the default tests configuration, remember to change INTERFACE_NAME to your *podman* network interface:
```
cp config-template-for-tests.py legs/config.py
```
Get the network namespace currently used by podman:
```
ps aux | grep -i netns
```
You should receive an output containing a process similar to this:
```
/usr/bin/slirp4netns --disable-host-loopback --mtu=65520 --enable-sandbox --enable-seccomp --enable-ipv6 -c -r 3 --netns-type=path /run/user/1000/netns/rootless-netns-de4da728901569ceabc9 tap0
```
In this case, the network namespace is the following:
```
/run/user/1000/netns/rootless-netns-de4da728901569ceabc9
```
Run tests with pytest using the found network namespace:
```
podman unshare nsenter --net=/run/user/1000/netns/rootless-netns-de4da728901569ceabc9 venv/bin/pytest
```
Shut down the testing environment:
```
podman-compose down
```

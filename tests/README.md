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
cd tests && ./rebuild-and-restart-tests.sh
```
Go back to the root of the project:
```
cd ..
```
Copy the default tests configuration, if needed change INTERFACE_NAME to your **podman container** network interface:
```
cp config-template-for-tests.py legs/config.py
```
Add the development FreeIPA's hostname to [your hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) pointing at localhost.
On Linux, /etc/hosts should contain:
```
127.0.0.1 ipa.example.test
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

## Accessing FreeIPA WebUI:
To access the FreeIPA WebUI while avoiding running podman as root, we must manually redirect connections from port 443 to port 4443.
Run this command:
```
sudo socat TCP-LISTEN:443,fork TCP:127.0.0.1:4443
```
And access the WebUI at https://ipa.example.test/ipa/ui/

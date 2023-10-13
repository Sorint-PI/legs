# podman build image
# podman up (TODO check whether podman up updates the image)

echo "Running podman-compose down"
podman-compose down

echo "Running podman-compose up"
podman-compose up -d

echo "Waiting 30 seconds"
sleep 30s

echo "Running seeding process"
../venv/bin/python seed.py

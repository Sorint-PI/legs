# podman build image
# podman up (TODO check whether podman up updates the image)

echo "Running podman-compose down"
podman-compose down

echo "Running podman-compose up"
podman-compose up -d

IPA_RUNNING=1
while [ $IPA_RUNNING -ne 0 ]
do
    echo "Waiting for IPA to start correctly"
    sleep 2
    podman exec -it tests_integration-tests-freeipa-server-container_1 ipactl status
    IPA_RUNNING=$?
done

KEYCLOAK_RUNNING=1
while [ $KEYCLOAK_RUNNING -ne 0 ]
do
    echo "Waiting for Keycloak to start correctly"
    sleep 2
    keycloak_health_response=$(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:8080/health)
    if [[ $keycloak_health_response == "200" ]] ; then
        KEYCLOAK_RUNNING=0
    fi
done


echo "Running seeding process"
../venv/bin/python seed.py
podman exec -it tests_integration-tests-freeipa-server-container_1 bash -c "echo 'directorymanager' | kinit username"
podman exec -it tests_integration-tests-freeipa-server-container_1 ipa user-add testuser1 --first=Test --last=User

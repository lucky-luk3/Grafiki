#!/bin/sh


echo ">>>>  Right before SG initialization <<<<"

while true
do
    netstat -uplnt | grep :5432 | grep LISTEN > /dev/null
    verifier=$?
    if [ 0 = $verifier ]
        then
            echo "Running Postgres"
			cd /opt/grafiki
			python3 manage.py migrate
			python3 manage.py runserver 0.0.0.0:8000
            break
        else
            echo "ES is not running yet"
            sleep 5
    fi
done

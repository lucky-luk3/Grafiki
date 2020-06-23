# Install PostgreSQL
apt install postgresql postgresql-contrib -y
# Config PostgreSQL
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'grafiki';"
sudo -u postgres psql -q -c "create database grafiki;"
sudo -u postgres psql -d grafiki -a -f initial.sql

# Install dependencies
apt install python3, python3-pip, django, libpq-dev, python3-psycopg2, python-djangorestframework, python-django-crispy-forms, python-evtx -y
pip3 install elasticsearch_dsl
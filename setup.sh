# Install PostgreSQL
apt install postgresql postgresql-contrib -y
# Config PostgreSQL
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'grafiki';"
sudo -u postgres psql -q -c "create database grafiki;"
sudo -u postgres psql -d grafiki -a -f initial.sql

# Install dependencies
sudo apt install python3 python3-pip libpq-dev -y
pip3 install elasticsearch_dsl django psycopg2 djangorestframework django-crispy-forms evtx==0.6.7
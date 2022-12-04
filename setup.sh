# Install PostgreSQL
apt install postgresql postgresql-contrib -y
# Config PostgreSQL
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'grafiki';"
sudo -u postgres psql -q -c "create database grafiki;"
cp initial.sql /tmp
sudo -u postgres psql -d grafiki -a -f /tmp/initial.sql
sudo -- sh -c -e "echo '127.0.0.1 grafiki.local' >> /etc/hosts"

# Install dependencies
sudo apt install python3 python3-pip libpq-dev -y
pip3 install elasticsearch_dsl django psycopg2 djangorestframework django-crispy-forms evtx
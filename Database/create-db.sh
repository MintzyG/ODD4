#!/bin/bash

DATABASE=${DATABASE:-"scti-db"}
DATABASE_USER=${DATABASE_USER:-"scti-user"}
DATABASE_PASS=${DATABASE_PASS:-"scti#01"}

# Create the database
psql -U postgres -c "CREATE DATABASE \"$DATABASE\";"

# Create the user with a password
psql -U postgres -c "CREATE USER \"$DATABASE_USER\" WITH ENCRYPTED PASSWORD '$DATABASE_PASS';"

# Grant all privileges on the database to the user
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE \"$DATABASE\" TO \"$DATABASE_USER\";"

# Allow the user to create schemas and tables
psql -U postgres -c "ALTER USER \"$DATABASE_USER\" CREATEDB;"

# Connect to the database and grant privileges on all schemas and tables
psql -U postgres -d "$DATABASE" -c "GRANT ALL PRIVILEGES ON SCHEMA public TO \"$DATABASE_USER\";"
psql -U postgres -d "$DATABASE" -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"$DATABASE_USER\";"

echo "Database setup completed successfully!"

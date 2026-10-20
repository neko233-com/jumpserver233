CREATE ROLE qadb LOGIN PASSWORD 'synthetic-postgres-query-233';
CREATE DATABASE qa OWNER qadb;
-- Dedicated disposable PAM authority; ordinary query fixtures keep their role.
CREATE ROLE pam_admin LOGIN CREATEROLE PASSWORD 'synthetic-pam-admin-233';

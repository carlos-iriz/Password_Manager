#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#
# Password Manager Application
#
# The application provides a secure way for the management and storage of passwords utilizing a PostgreSQL database
# to store user data. It utilizes AES encryption to protect user passwords and bcrypt hashing for securing the master password
# which is used as a key in order to encrypt all of the stored passwords within the application.
# Users can store, view, add, and delete their passwords, with all sensitive data stored within the database
# using encryption to maintain security.
#
# Key Features:
# - AES encryption for password storage and retrieval
# - Bcrypt hashing for secure authentication of the master password
# - PostgreSQL database integration, utilizing views for efficient management of stored passwords
# - User-friendly interface for adding, retrieving, and deleting passwords
#
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

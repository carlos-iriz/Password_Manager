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

import psycopg2
from Crypto.Cipher import AES
import bcrypt

# Credentials for database
hostname = 'localhost'
database = 'Password Database'
username = 'postgres'
pwd = 'pops'
port_id = 5432

conn = None
cursor = None

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Function encrypts a message using a given key
# Within the context of this application each password will be encrypted using the master password provided

def encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Function decrypts a message using the nonce and tag that where generated when the text was encrypted along with the master key
# Within the context of this application each password will be deencrypted using the master password to display the passwords
# stored in the database

def decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Login function, determines if user already has an account by referencing the database. If the user doesn't already have an
# account the program will allow the user to create one. If the user has an account they will be prompted to input their
# credentials in order to gain access to the password application.

def login():
    global cursor, conn
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM User_info;")
        result = cursor.fetchone()

        if result[0] == 0:  # If there is no entry for the master password, user is new so create master password
            master_password = input('Enter a 16-character length master password: ').encode('ascii')

            # Loop until the password length is correct
            while len(master_password) != 16:
                print("Invalid key length. The key MUST be 16 characters long.")
                master_password = input('Enter a 16-character length master password: ').encode('ascii')

            # Hashing the password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(master_password, salt)

            query = """
                    INSERT INTO User_info (master_password)
                    VALUES (%s);
                    """
            value = (hashed_password,)  # Ensure hashed_password is stored as bytes

            try:
                cursor.execute(query, value)
                conn.commit()

            except psycopg2.Error as err:
                print(f"Error: {err}")

        else: #If user reaches this block they already have an account so we prompt to login to the account

            # Fetch master password from database
            query = "SELECT master_password FROM User_info LIMIT 1;"
            cursor.execute(query)

            result = cursor.fetchone()
            stored_hashed_password = result[0]

            # Check if the stored password is a memoryview (Type returned by psycopg2 for BYTEA columns)
            if isinstance(stored_hashed_password, memoryview):
                stored_hashed_password = stored_hashed_password.tobytes() # Convert the memoryview object to bytes

            # Loops until user is able to enter correct password (To add: Implement limited attempts system)
            while True:
                input_password = input('Enter password to access password manager: ').encode('ascii')

                # Compare hashed input password to master password in database
                if bcrypt.checkpw(input_password, stored_hashed_password):
                    print("Password has been accepted")
                    return input_password
                else:
                    print('Incorrect password, please enter the correct password.')

    except psycopg2.Error as error:
        print(f"Error: {error}")

    finally:
        if cursor is not None:
            cursor.close()

    return None


#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Function pulls passwords from PasswordsView which allows the user to view all the critial info that they need
# Since they have no need to view anything from the database besides the saved passwords and their corresponding
# website names only those two values are shown using a view created from the table that holds the info they need

def display_passwords(master_password):
    global cursor, conn

    try:
        # Ensure the cursor is open and valid
        if cursor is None or cursor.closed:
            cursor = conn.cursor()

        # Retrieve information from the PasswordsView
        query = "SELECT website, password, nonce, tag FROM PasswordsView;"
        cursor.execute(query)

        passwords = cursor.fetchall()
        
        # If there are passwords stored in the database
        if passwords:
            print("Stored Websites and Passwords:")

            #Loops through all entries in the database and decrypts them to display to user
            for entry in passwords:
                website, encrypted_password, nonce, tag = entry
                decrypted_password = decrypt(nonce, encrypted_password, tag, master_password)
                print(f"Website: {website}, Password: {decrypted_password}")

        # User has no passwords stored in the database
        else:
            print("No entries found in Passwords")

    except psycopg2.Error as error:
        print(f"Error: {error}")

    print('\n')

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Allows the user to add an additional entry to the database which allows for them to store an additional password
# in the application. The password is encrypted using the encrypt function in order to store it in the database safely

def add_password(master_password):
    global cursor, conn

    try:
        cursor = conn.cursor()

        # Prompt the user to input the website and desired password
        website_name = input("Enter the website name: ")
        input_pass = input("Enter the password for this website: ")

        # Encrypt password
        nonce, encrypted_password, tag = encrypt(input_pass, master_password)

        # Insert into database
        insert_query = """
        INSERT INTO Passwords (website, password, nonce, tag)
        VALUES (%s, %s, %s, %s);
        """
        values = (website_name,encrypted_password , nonce, tag)

        cursor.execute(insert_query, values)
        conn.commit()
        print(f"Password for {website_name} has been successfully added\n\n")

    except psycopg2.Error as error:
        print(f"Error: {error}")

    finally:
        if cursor is not None:
            cursor.close()

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Allows the user to remove an entry in the database which allows them to remove a saved password from the application

def remove_password(master_password):
    global cursor, conn

    try:
        # Ensure the cursor is open and valid
        if cursor is None or cursor.closed:
            cursor = conn.cursor()

        # Display passwords with the provided master_password (saved on login)
        display_passwords(master_password)

        #To add: Input validation here to ensure that the user is picking a website that is stored in the database

        # User selects which password to delete
        selection = input('Enter the name of the website you wish to delete the password for: ')

        query = """
        DELETE FROM Passwords WHERE website = %s;
        """
        value = (selection,)

        cursor.execute(query, value)
        conn.commit()

        print("Password successfully deleted\n\n")

    except psycopg2.Error as error:
        print(f"Error: {error}")


#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Allows user to delete all data in database which allows for them to delete their master password and restart the
# application with a "new account" which allows them to have a different master password

def delete_all_tables():
    global cursor, conn

    try:
        cursor = conn.cursor()

        drop_passwords = "DROP TABLE IF EXISTS Passwords CASCADE;"
        drop_user_info = "DROP TABLE IF EXISTS User_info CASCADE;"
        cursor.execute(drop_passwords)
        cursor.execute(drop_user_info)

        conn.commit()
        print("All tables and views have been deleted successfully\n")

    except psycopg2.Error as error:
        print(f"Error: {error}")

    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
    
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Main
def main():
    # Connection to database is established and create tables if they don't already exist

    global conn, cursor

    try:
        conn = psycopg2.connect(
            host=hostname,
            dbname=database,
            user=username,
            password=pwd,
            port=port_id
        )

        cursor = conn.cursor()

        # Creates tables in database only if the tables are not already in database

        create_user_info_table = '''
            CREATE TABLE IF NOT EXISTS User_info (
            master_password BYTEA PRIMARY KEY  -- BYTEA for storing binary data like hashed passwords
        );'''

        create_passwords_table = '''
            CREATE TABLE IF NOT EXISTS Passwords (
            website VARCHAR(255) PRIMARY KEY,
            password BYTEA NOT NULL,
            nonce BYTEA NOT NULL,
            tag BYTEA NOT NULL
        );'''

        create_passwords_view = '''
            DROP VIEW IF EXISTS PasswordsView;

            CREATE VIEW PasswordsView AS
            SELECT password, website, nonce, tag
            FROM Passwords;
        '''

        # Executes creation statements in database

        cursor.execute(create_user_info_table)
        cursor.execute(create_passwords_table)
        cursor.execute(create_passwords_view)

        conn.commit()

        master_pass = login()

        menu = '0'

        print("\nWelcome to Password Manager, please select function:\n")

        # Main loop for program allows user to pick between all program functions
        # Display passwords, add password, remove password, and deletion of all data
        while(True):
            try:
                menu = int(input('Please select function (input number in terminal):\n'
                                'Exit:                  0\n'                             
                                'Display Passwords:     1\n'
                                'Add Password:          2\n'
                                'Remove Password:       3\n'
                                'Delete all data:       4\n'
                                'Menu Selection:        '))    

            except ValueError:
                print('\nInput not valid, please select a numerical value from menu or enter 0 to quit\n')

            if menu == 0:
                print('\nThank you for using the tool! Goodbye!\n')
                break

            elif menu == 1:
                print('\nDisplay Passwords:\n')
                display_passwords(master_pass)

            elif menu == 2:
                print('\nAdd Password:\n')
                add_password(master_pass)

            elif menu == 3:
                print('\nRemove Password:\n')
                remove_password(master_pass)

            elif menu == 4:
                print('\nDeleting all data...\n')
                delete_all_tables()
                break

            else:
                print('\nPlease select valid input from menu\n')

    except psycopg2.Error as error:
        print(f"Error: {error}")

    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

    print('All done!')

main()

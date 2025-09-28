# Rot-Chat

Rot-Chat is a self-hosted, feature-rich PHP web chat application designed for privacy and community engagement, with specific optimizations for use on the Tor network. It offers a high degree of customization and administrative control.

## Features

* **Real-time Messaging**: Live chat updates without needing to refresh the page.
* **User Roles & Permissions**: Granular control with roles like Admin, Moderator, Trusted, and User.
* **Guest Access**: Allows anonymous users to participate with configurable limits.
* **Admin Panel**: Comprehensive dashboard to manage users, settings, and monitor chat activity.
* **Customization**: Users can change their color, and admins can modify site-wide styles and settings.
* **File Uploads**: Registered users can share images, documents, and other files.
* **Private Messaging**: Secure one-to-one conversations between registered users.

## Getting Started

Follow these instructions to get your Rot-Chat instance up and running.

### Prerequisites

* A web server with PHP version 7.4 or higher.
* A MySQL or MariaDB database.
* Access to the command line or a file manager to upload files.

### Installation

1.  **Download the Project**: Download all the project files and upload them to your web server.
2.  **Create a Database**: Create a new, empty database and a database user with full privileges for that database. Note down the database name, username, and password.
3.  **Configure the Application**:
    * Find the file `config.example.php` and rename it to `config.php`.
    * Open `config.php` in a text editor.
    * Replace the placeholder values for `$db_host`, `$db_name`, `$db_user`, and `$db_pass` with your actual database credentials.
4.  **Run the Setup Script**:
    * Open your web browser and navigate to `your-website.com/db_setup.php`.
    * The script will run and set up all the necessary database tables. You should see a success message when it's finished.
5.  **Secure Your Installation**:
    * **IMPORTANT**: After a successful setup, **delete the `db_setup.php` file** from your server. Leaving it accessible is a security risk.
    * It is also recommended to delete `emergency_clear_sessions.php` unless you are actively troubleshooting.

## Usage

Once the installation is complete, navigate to your website's main URL. You can register an account or log in as a guest to start chatting. The first user to register will automatically be granted Admin privileges.

---
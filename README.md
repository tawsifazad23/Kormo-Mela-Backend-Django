# Kormo Mela Backend - Empowering Service Providers and Customers in Bangladesh

## Overview

Kormo Mela is a backend platform built using **Django** and **Django REST Framework** to power the services of Kormo Mela, a networking platform connecting customers and verified service providers in Bangladesh. This backend API manages user authentication, job postings, service provider listings, real-time communication, and secure payment processing. It also handles the interaction with the PostgreSQL database for data storage and management.

## Key Features

- **User Verification**: Each user is verified with a National ID, ensuring secure and trusted interactions.
- **Role-Based Authentication**: The backend supports different user roles (customer, service provider) with Django's robust authentication system.
- **Job Listings & Bidding**: Service providers can view and bid on jobs, and customers can choose providers based on reviews, skills, and availability.
- **Secure Payments**: Integration with secure payment gateways to handle transactions between customers and service providers.
- **Real-Time Communication**: Service providers and customers can communicate via built-in chat functionality using WebSockets.

## Technologies Used

- **Backend Framework**: Django, Django REST Framework
- **Database**: PostgreSQL
- **Real-time Notifications**: Firebase Cloud Messaging
- **Version Control**: Git
- **Hosting**: The backend is set up for cloud deployment with Docker support.

## Setup Instructions

To get the backend of Kormo Mela running locally, follow the steps below:

### Prerequisites

1. **Python**: Make sure Python 3.x is installed on your machine.
2. **PostgreSQL**: You need PostgreSQL installed and running locally or on a remote server.

### Step 1: Clone the Repository

```bash
git clone https://github.com/tawsifazad23/Kormo-Mela-Backend-Django.git
cd Kormo-Mela-Backend-Django
```

### Step 2: Set Up a Virtual Environment

Create a virtual environment to isolate dependencies.

```bash
python3 -m venv env
source env/bin/activate
```

### Step 3: Install Dependencies

Install Django, Django REST framework, and PostgreSQL libraries.

```bash
pip install django djangorestframework psycopg2-binary
```

### Step 4: Database Setup

Configure the PostgreSQL database:

1. Make sure PostgreSQL is running. You can use the command `psql` to check your PostgreSQL connection.
2. Create a database for Kormo Mela:

```sql
CREATE DATABASE kormo_mela;
CREATE USER azad2002 WITH PASSWORD 'your_password';
ALTER ROLE azad2002 SET client_encoding TO 'utf8';
ALTER ROLE azad2002 SET default_transaction_isolation TO 'read committed';
ALTER ROLE azad2002 SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE kormo_mela TO azad2002;
```

3. Update your **`settings.py`** to include the correct database credentials:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'kormo_mela',
        'USER': 'azad2002',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',  # or your PostgreSQL host
        'PORT': '5432',
    }
}
```

### Step 5: Migrate the Database

Apply the migrations to create the necessary database tables.

```bash
python manage.py migrate
```

### Step 6: Create a Superuser (Admin)

Create a superuser account to access the Django admin panel.

```bash
python manage.py createsuperuser
```

Follow the prompts to create your superuser account.

### Step 7: Run the Server

Now, you're ready to run the Django development server.

```bash
python manage.py runserver
```

The backend will be accessible at `http://127.0.0.1:8000/`.

## API Endpoints

Some key API endpoints you can interact with:

- **User Authentication**: 
  - `POST /api/auth/login/`: Log in users.
  - `POST /api/auth/signup/`: Sign up new users.
  
- **Service Providers**: 
  - `GET /api/service-providers/`: List all service providers.
  - `POST /api/service-providers/`: Create a new service provider.

- **Jobs**:
  - `GET /api/jobs/`: List all available jobs.
  - `POST /api/jobs/`: Create a new job.

- **Chat**: 
  - `GET /api/chat/`: Retrieve messages between users.
  - `POST /api/chat/`: Send a message.

## Environment Variables

You should also define the necessary environment variables for security and configuration, such as:

```bash
SECRET_KEY='your_secret_key'
DEBUG=True
DB_NAME=kormo_mela
DB_USER=azad2002
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
```

## IP Setup

To find your local machine's IP address for the setup:

```bash
ifconfig | grep inet
```

## Additional Commands

### Running Tests

To run tests, you can use Django's built-in testing framework:

```bash
python manage.py test
```

### Resetting the Project

If you need to reset the project for any reason:

```bash
python manage.py flush
```

### Deploying

If you are deploying to production, make sure to disable `DEBUG`, set up a proper `ALLOWED_HOSTS`, and configure a production-ready database.

## Learn More

- [Django documentation](https://docs.djangoproject.com/en/stable/): Learn more about Django's features and capabilities.
- [Django REST framework](https://www.django-rest-framework.org/): Documentation for building APIs with Django.

## Conclusion

Kormo Mela is built to empower service providers and customers through secure and efficient connections. The backend handles all essential operations, from user authentication to job management, ensuring a reliable experience for all users. 

We look forward to scaling the platform and enhancing its functionalities to create a greater impact!
```


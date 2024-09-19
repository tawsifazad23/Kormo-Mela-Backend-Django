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

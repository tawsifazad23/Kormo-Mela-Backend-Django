from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.db.models.signals import post_save
from django.dispatch import receiver

class User(models.Model):
    id = models.AutoField(primary_key=True)  # AutoField for primary key
    first_name = models.CharField(max_length=255, null=True)
    last_name = models.CharField(max_length=255, null=True)
    email = models.EmailField(unique=True, null=True)
    password = models.CharField(max_length=255, null=True)
    phone = models.CharField(max_length=255, null=True)
    address = models.CharField(max_length=255, null=True)
    rating = models.IntegerField(null=True)
    nid = models.CharField(max_length=255, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_photo = models.CharField(null=True, blank=True)

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    occupation = models.CharField(max_length=255, null=True)
    email = models.EmailField()  # Removed unique constraint
    address = models.CharField(max_length=255, null=True)
    rating = models.FloatField(null=True)

class ServiceProvider(models.Model):
    service_provider_id = models.CharField(max_length=255, null=True)
    years_in_industry = models.IntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='service_providers')
    intro_video = models.URLField(blank=True, null=True)
    app_verified_date = models.DateField()

class Role(models.Model):
    ROLE_TYPE_CHOICES = (
        (1, 'Type 1'),
        (2, 'Type 2'),
    )
    type = models.IntegerField(choices=ROLE_TYPE_CHOICES)

class Driver(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='driver')
    license_number = models.CharField(max_length=255, null=True)
    vehicle_type = models.CharField(max_length=255, null=True)

class Maid(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='maid')
    experience_years = models.IntegerField()
    skills = models.TextField()

class JobPosting(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='job_postings')
    service_type = models.CharField(max_length=255, null=True)
    service_period = models.CharField(max_length=255, null=True)
    service_rate = models.DecimalField(max_digits=10, decimal_places=2)
    onboarding_location = models.CharField(max_length=255, null=True)
    job_summary = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ServiceProviderRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('send_request', 'send_request'),
        ('rejected', 'Rejected'),
        ('accepted', 'Accepted')
    ]
    job_posting = models.ForeignKey(JobPosting, on_delete=models.CASCADE, related_name='service_provider_requests')
    service_provider = models.ForeignKey(User, on_delete=models.CASCADE, related_name='service_provider_requests')
    request_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    sent_request_time = models.DateTimeField(auto_now_add=True)
    accepted_request_time = models.DateTimeField(blank=True, null=True)
    rejected_request_time = models.DateTimeField(blank=True, null=True)

class AcceptedRequest(models.Model):
    service_provider_request = models.ForeignKey(ServiceProviderRequest, on_delete=models.CASCADE, related_name='accepted_requests')
    accepted_time = models.DateTimeField(default=timezone.now)

class Chat(models.Model):
    STATUS_CHOICES = (
        ('deleted', 'Deleted'),
        ('expired', 'Expired'),
        ('confirmed', 'Confirmed'),
        ('messaging', 'Messaging'),
    )
    service_provider_request = models.ForeignKey(ServiceProviderRequest, on_delete=models.CASCADE, related_name='chats')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='messaging')

class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    time = models.DateTimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)
class Transaction(models.Model):
    job_posting = models.ForeignKey(JobPosting, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    hired_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hired_transactions')
    rate = models.DecimalField(max_digits=10, decimal_places=2)
    datetime = models.DateTimeField(auto_now_add=True)
    payment_method = models.CharField(max_length=255, null=True)
    additional_info = models.TextField(null=True, blank=True)  # Added field



class Hiring(models.Model):
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='customer_hirings')
    service_provider = models.ForeignKey(User, on_delete=models.CASCADE, related_name='service_provider_hirings')
    customer_rating = models.IntegerField(null=True, blank=True)  # Allow null values
    service_provider_rating = models.IntegerField(null=True, blank=True)  # Allow null values
    hired_date = models.DateTimeField(auto_now_add=True)
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE)


class Notification(models.Model):
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(null=True, blank=True)


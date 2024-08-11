
# from rest_framework import serializers
# from django.contrib.auth import get_user_model
# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from .models import ServiceProviderRequest, JobPosting, Driver, User


# class DriverSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Driver
#         fields = ['license_number', 'vehicle_type']

# class UserSerializer(serializers.ModelSerializer):
    
#     class Meta:
#         model = User
#         fields = ['id', 'first_name', 'last_name', 'email', 'phone', 'address', 'rating', 'driver']

# class RegisterSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('email', 'password', 'first_name', 'last_name', 'phone', 'address', 'nid', 'date_of_birth')
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         user = User.objects.create_user(**validated_data)
#         return user

# class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
#     @classmethod
#     def get_token(cls, user):
#         token = super().get_token(user)
#         token['email'] = user.email
#         return token

# class ServiceProviderRequestSerializer(serializers.ModelSerializer):
#     service_provider = UserSerializer()

#     class Meta:
#         model = ServiceProviderRequest
#         fields = ['id', 'job_posting', 'service_provider', 'request_status', 'sent_request_time']

# class JobPostingSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = JobPosting
#         fields = [
#             'id',
#             'service_type',
#             'service_period',
#             'service_rate',
#             'onboarding_location',
#             'job_summary',
#             'status',
#             'created_at',
#             'updated_at',
#         ]


# from rest_framework import serializers
# from .models import Chat

# class ChatSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Chat
#         fields = ['id', 'sender', 'receiver', 'accepted_request', 'message', 'time', 'deleted_user', 'status']

from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import ServiceProviderRequest, JobPosting, Driver, User, Chat, Transaction, Hiring

class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        fields = ['license_number', 'vehicle_type']

class UserSerializer(serializers.ModelSerializer):
    driver = DriverSerializer()

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone', 'address', 'rating', 'driver']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'last_name', 'phone', 'address', 'nid', 'date_of_birth')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        return token

class ServiceProviderRequestSerializer(serializers.ModelSerializer):
    service_provider = UserSerializer()

    class Meta:
        model = ServiceProviderRequest
        fields = ['id', 'job_posting', 'service_provider', 'request_status', 'sent_request_time']

class JobPostingSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobPosting
        fields = [
            'id',
            'service_type',
            'service_period',
            'service_rate',
            'onboarding_location',
            'job_summary',
            'status',
            'created_at',
            'updated_at',
        ]

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = ['id', 'sender', 'receiver', 'accepted_request', 'message', 'time', 'deleted_user', 'status']

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id', 'user', 'hired_by', 'rate', 'datetime', 'payment_method', 'additional_info']

class HiringSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hiring
        fields = ['id', 'customer', 'service_provider', 'customer_rating', 'service_provider_rating', 'hired_date', 'transaction']

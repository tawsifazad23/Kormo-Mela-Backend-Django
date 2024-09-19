import json
import jwt
import datetime
import logging
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core import serializers
from django.conf import settings
from django.middleware.csrf import get_token
from django.contrib.auth.hashers import make_password, check_password
from .models import User, Customer, JobPosting, AcceptedRequest
# views.py
from .serializers import JobPostingSerializer  # Import the serializer at the top
from django.core.files.storage import FileSystemStorage
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# View to get all users
def get_users(request):
    user = User.objects.all()
    data = serializers.serialize("json", user)
    return HttpResponse(data)

# View to get all accepted requests
def get_accepted_requests(request):
    acceptedrequest = AcceptedRequest.objects.all()
    data = serializers.serialize("json", acceptedrequest)
    return HttpResponse(data)

# View to add a new user
@csrf_exempt
def add_new_user(request):
    data = json.loads(request.body)
    User.objects.create(first_name=data["first_name"], last_name=data["last_name"])
    return HttpResponse("fake response")

# from django.utils.decorators import method_decorator
# from django.views import View
# from django.views.decorators.csrf import csrf_exempt
# from django.contrib.auth.hashers import make_password
# from django.conf import settings
# from django.http import JsonResponse
# import jwt
# import json
# import datetime
# import logging

# from .models import User, Driver, Maid, ServiceProvider, Customer

# logging.basicConfig(level=logging.ERROR)
# logger = logging.getLogger(__name__)

# @csrf_exempt
# def signup_view_customer(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)
#             first_name = data.get('first_name')
#             last_name = data.get('last_name')
#             email = data.get('email')
#             confirm_email = data.get('confirm_email')
#             password = data.get('password')
#             confirm_password = data.get('confirm_password')
#             phone = data.get('phone')
#             address = data.get('address')
#             nid = data.get('nid')
#             date_of_birth = data.get('date_of_birth')
#             occupation = data.get('occupation')

#             # Validate required fields
#             if not all([first_name, last_name, email, confirm_email, password, confirm_password, phone, address, nid, date_of_birth, occupation]):
#                 return JsonResponse({'message': 'Missing fields'}, status=400)

#             if email != confirm_email:
#                 return JsonResponse({'message': 'Emails do not match'}, status=400)
            
#             if password != confirm_password:
#                 return JsonResponse({'message': 'Passwords do not match'}, status=400)

#             # Check if user already exists
#             if User.objects.filter(email=email).exists():
#                 return JsonResponse({'message': 'User already exists'}, status=400)

#             # Hash the password
#             hashed_password = make_password(password)

#             # Create new user
#             user = User.objects.create(
#                 first_name=first_name,
#                 last_name=last_name,
#                 email=email,
#                 password=hashed_password,
#                 phone=phone,
#                 address=address,
#                 nid=nid,
#                 date_of_birth=date_of_birth,
#             )

#             # Create customer details
#             Customer.objects.create(
#                 user=user,
#                 occupation=occupation,
#                 email=email,
#                 address=address,
#             )

#             # Generate JWT token
#             token = jwt.encode({
#                 'user_id': user.id,
#                 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
#             }, settings.SECRET_KEY, algorithm='HS256')

#             return JsonResponse({'message': 'User created successfully!', 'token': token})
#         except Exception as e:
#             logger.error(f'Signup failed: {str(e)}')
#             return JsonResponse({'message': 'Signup failed', 'error': str(e)}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)
import json
import jwt
import datetime
import logging
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import make_password
from .models import User, Customer

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

@csrf_exempt
def signup_view_customer(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            confirm_email = data.get('confirm_email')
            password = data.get('password')
            confirm_password = data.get('confirm_password')
            phone = data.get('phone')
            address = data.get('address')
            nid = data.get('nid')
            date_of_birth = data.get('date_of_birth')
            occupation = data.get('occupation')

            logger.debug("Received signup request with data: %s", data)

            # Validate required fields
            if not all([first_name, last_name, email, confirm_email, password, confirm_password, phone, address, nid, date_of_birth, occupation]):
                logger.error("Missing fields in signup request")
                return JsonResponse({'message': 'Missing fields'}, status=400)

            if email != confirm_email:
                logger.error("Emails do not match")
                return JsonResponse({'message': 'Emails do not match'}, status=400)
            
            if password != confirm_password:
                logger.error("Passwords do not match")
                return JsonResponse({'message': 'Passwords do not match'}, status=400)

            # Check if user already exists
            if User.objects.filter(email=email).exists():
                logger.error("User already exists with email: %s", email)
                return JsonResponse({'message': 'User already exists'}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Create new user
            user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=hashed_password,
                phone=phone,
                address=address,
                nid=nid,
                date_of_birth=date_of_birth,
            )

            # Create customer details
            Customer.objects.create(
                user=user,
                occupation=occupation,
                email=email,
                address=address,
            )

            # Generate JWT token
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')

            logger.info("User created successfully with email: %s", email)
            return JsonResponse({'message': 'User created successfully!', 'token': token})
        except Exception as e:
            logger.error(f'Signup failed: {str(e)}')
            return JsonResponse({'message': 'Signup failed', 'error': str(e)}, status=500)
    else:
        logger.error("Invalid request method")
        return JsonResponse({'message': 'Invalid request method'}, status=405)

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

@method_decorator(csrf_exempt, name='dispatch')
class SignupViewServiceProvider(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            
            # Extracting data from the request
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            confirm_email = data.get('confirm_email')
            password = data.get('password')
            confirm_password = data.get('confirm_password')
            phone = data.get('phone')
            address = data.get('address')
            nid = data.get('nid')
            date_of_birth = data.get('date_of_birth')
            role = data.get('role')
            years_in_industry = data.get('years_in_industry', 0)
            intro_video = data.get('intro_video')
            app_verified_date = data.get('app_verified_date', datetime.datetime.now().isoformat())

            # Validate required fields
            if not all([first_name, last_name, email, confirm_email, password, confirm_password, phone, address, nid, date_of_birth, role]):
                return JsonResponse({'error': 'All fields are required'}, status=400)
            
            if email != confirm_email:
                return JsonResponse({'error': 'Emails do not match'}, status=400)
                
            if password != confirm_password:
                return JsonResponse({'error': 'Passwords do not match'}, status=400)
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already exists'}, status=400)
            
            # Create User
            user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=make_password(password),
                phone=phone,
                address=address,
                nid=nid,
                date_of_birth=date_of_birth
            )

            # Create specific role-based data
            if role == 'driver':
                license_number = data.get('license_number')
                vehicle_type = "All types"  # Default value for vehicle type
                
                if not license_number:
                    return JsonResponse({'error': 'License number is required for drivers'}, status=400)
                
                Driver.objects.create(
                    user=user,
                    license_number=license_number,
                    vehicle_type=vehicle_type
                )
            
            elif role == 'maid':
                experience_years = data.get('experience_years')
                skills = data.get('skills')
                
                if not all([experience_years, skills]):
                    return JsonResponse({'error': 'Experience years and skills are required for maids'}, status=400)
                
                Maid.objects.create(
                    user=user,
                    experience_years=experience_years,
                    skills=skills
                )

            # Create ServiceProvider entry
            ServiceProvider.objects.create(
                user=user,
                years_in_industry=years_in_industry,
                intro_video=intro_video,
                app_verified_date=app_verified_date
            )

            # Generate JWT token
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')
            
            return JsonResponse({'message': 'Signup successful!', 'token': token})
        except Exception as e:
            logger.error(f'Signup failed: {str(e)}')
            return JsonResponse({'error': 'Signup failed', 'details': str(e)}, status=500)

import json
import jwt
import datetime
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User, Customer
import datetime
import logging
import jwt
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import check_password
from .models import User, Customer
from datetime import datetime, timedelta
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        user = User.objects.filter(email=email).first()

        if user and check_password(password, user.password):
            # Check if the user is a customer
            try:
                customer = user.customer
            except Customer.DoesNotExist:
                return JsonResponse({'message': 'Login allowed for customers only.'}, status=401)

            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')
            return JsonResponse({'message': 'Login successful!', 'token': token})
        else:
            return JsonResponse({'message': 'Invalid email or password.'}, status=401)
    return JsonResponse({'message': 'Invalid request method'}, status=405)

@csrf_exempt
def protected_view(request):
    token = request.META.get('HTTP_AUTHORIZATION', None)
    if token is None:
        return JsonResponse({'message': 'Token not provided'}, status=403)

    decoded_token = decode_jwt(token)
    if 'error' in decoded_token:
        return JsonResponse({'message': decoded_token['error']}, status=403)

    user_id = decoded_token['user_id']
    user = User.objects.get(id=user_id)

    # Now you can access the user information and return the protected resource
    return JsonResponse({'message': 'This is a protected view', 'user': user.first_name})

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from django.http import JsonResponse
from django.conf import settings
from rest_framework.decorators import api_view
import jwt
from .models import User

@api_view(['GET'])
def profile_view(request):
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded.get('user_id')
        if not user_id:
            return JsonResponse({'message': 'Invalid token payload'}, status=401)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)

        # Construct the full URL for the profile photo
        if user.profile_photo:
            profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + 'users/images/profilepic/' + user.profile_photo.name)
        else:
            profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

        user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            'rating': user.rating,
            'nid': user.nid,
            'date_of_birth': user.date_of_birth,
            'updated_at': user.updated_at,
            'profile_photo': profile_photo_url,
        }
        return JsonResponse({'user': user_data}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    except Exception as e:
        # Log the error for debugging purposes
        logger.error(f"Error fetching profile: {e}")
        return JsonResponse({'message': 'An error occurred while fetching profile'}, status=500)

import json
import jwt
import datetime
import logging
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core import serializers
from django.conf import settings
from .models import User, JobPosting
from django.db.models import Q

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

@csrf_exempt
def job_posting(request):
    if request.method == 'POST':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded['user_id']
            user = User.objects.get(id=user_id)

            data = json.loads(request.body)
            service_type = data.get('service_type')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            service_rate = data.get('service_rate')
            onboarding_location = data.get('onboarding_location')
            job_summary = data.get('job_summary')

            # Ensure all required fields are present
            missing_fields = []
            if not service_type:
                missing_fields.append('service_type')
            if not start_date:
                missing_fields.append('start_date')
            if not end_date:
                missing_fields.append('end_date')
            if not service_rate:
                missing_fields.append('service_rate')
            if not onboarding_location:
                missing_fields.append('onboarding_location')
            if not job_summary:
                missing_fields.append('job_summary')

            if missing_fields:
                return JsonResponse({'message': 'Missing fields', 'fields': missing_fields}, status=400)

            job_posting = JobPosting.objects.create(
                user=user,
                service_type=service_type,
                service_period=f"{start_date} - {end_date}",
                service_rate=service_rate,
                onboarding_location=onboarding_location,
                job_summary=job_summary
            )

            return JsonResponse({'message': 'Job posting created successfully!'}, status=201)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    elif request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded['user_id']
            user = User.objects.get(id=user_id)

            job_postings = JobPosting.objects.filter(user=user)
            data = serializers.serialize('json', job_postings)
            return JsonResponse(data, safe=False)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

@csrf_exempt
def get_user_job_postings(request):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded['user_id']
            user = User.objects.get(id=user_id)

            # Order job postings by created_at in descending order
            job_postings = JobPosting.objects.filter(user=user).order_by('-created_at')
            data = [
                {
                    'id': job_posting.id,
                    'service_type': job_posting.service_type,
                    'service_period': job_posting.service_period,
                    'service_rate': job_posting.service_rate,
                    'onboarding_location': job_posting.onboarding_location,
                    'job_summary': job_posting.job_summary,
                    'created_at': job_posting.created_at,
                }
                for job_posting in job_postings
            ]
            return JsonResponse(data, safe=False)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import JobPosting
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import JobPosting

@csrf_exempt
def get_all_job_postings(request):
    if request.method == 'GET':
        try:
            job_postings = JobPosting.objects.all()
            data = [
                {
                    'service_type': job_posting.service_type,
                    'service_period': job_posting.service_period,
                    'service_rate': job_posting.service_rate,
                    'onboarding_location': job_posting.onboarding_location,
                    'job_summary': job_posting.job_summary,
                    'posted_by': job_posting.user.first_name,  # Assuming the JobPosting model has a ForeignKey to the User model
                }
                for job_posting in job_postings
            ]
            return JsonResponse(data, safe=False)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)



import json
import jwt
from datetime import datetime, timedelta
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import check_password
from .models import User, ServiceProvider

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

@csrf_exempt
def LoginViewServiceProvider(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                logger.error('Email and password are required.')
                return JsonResponse({'message': 'Email and password are required.'}, status=400)

            user = User.objects.filter(email=email).first()

            if not user:
                logger.error('User with the provided email does not exist.')
                return JsonResponse({'message': 'Invalid email or password.'}, status=401)

            if not check_password(password, user.password):
                logger.error('Invalid password for user: %s', email)
                return JsonResponse({'message': 'Invalid email or password.'}, status=401)

            if not ServiceProvider.objects.filter(user=user).exists():
                logger.error('User is not a service provider: %s', email)
                return JsonResponse({'message': 'User is not a service provider.'}, status=401)

            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')

            logger.info('Login successful for user: %s', email)
            return JsonResponse({'message': 'Login successful!', 'token': token})
        
        except Exception as e:
            logger.error('An error occurred during login: %s', str(e))
            return JsonResponse({'message': 'An error occurred during login.', 'error': str(e)}, status=500)
    else:
        logger.error('Invalid request method: %s', request.method)
        return JsonResponse({'message': 'Invalid request method'}, status=405)


from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, Message, User
import jwt
from django.conf import settings
import json
import time

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

@csrf_exempt
def get_messages_customer(request, chat_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            def event_stream():
                while True:
                    chat = Chat.objects.get(id=chat_id)
                    messages = Message.objects.filter(chat=chat).order_by('time')

                    messages_data = [
                        {
                            'id': msg.id,
                            'sender': msg.sender.first_name,
                            'message': msg.message,
                            'time': msg.time.isoformat(),
                            'isUserMessage': msg.sender.id == user_id
                        }
                        for msg in messages
                    ]
                    
                    yield f'data: {json.dumps(messages_data, default=datetime_handler)}\n\n'
                    time.sleep(2)  # Adjust the sleep time as needed

            response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Chat.DoesNotExist:
            return JsonResponse({'message': 'Chat not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)








from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import JobPosting, User
import jwt
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

@csrf_exempt
def delete_job_posting(request, job_id):
    if request.method == 'DELETE':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            job_posting = get_object_or_404(JobPosting, id=job_id, user=user)
            job_posting.delete()
            return JsonResponse({'message': 'Job posting deleted successfully!'}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)


@csrf_exempt
def accept_request(request, request_id):
    if request.method == 'POST':
        service_provider_request = get_object_or_404(ServiceProviderRequest, id=request_id)
        service_provider_request.request_status = 'accepted'
        service_provider_request.save()

        # Create a new chat
        chat = Chat.objects.create(service_provider_request=service_provider_request, status='messaging')

        # Add the initial message
        Message.objects.create(
            chat=chat,
            sender=service_provider_request.user,
            receiver=service_provider_request.service_provider,
            message="You can start chatting now"
        )

        return JsonResponse({'message': 'Request accepted and chat initiated successfully.'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def reject_request(request, request_id):
    if request.method == 'POST':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            service_request = get_object_or_404(ServiceProviderRequest, id=request_id, job_posting__user=user)

            if service_request.request_status not in ['send_request', 'accepted']:
                return JsonResponse({'message': 'Cannot reject a request that is not in send_request or accepted status'}, status=400)

            service_request.request_status = 'rejected'
            service_request.rejected_request_time = timezone.now()
            service_request.save()

            return JsonResponse({'message': 'Request rejected successfully!'}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse, StreamingHttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import ServiceProviderRequest, Chat, Message, User
# import jwt
# from django.conf import settings
# import json
# import time
# from datetime import datetime

# from django.db.models import Count, Q
# from django.http import JsonResponse, StreamingHttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import ServiceProviderRequest, Chat, Message, User
# import jwt
# from django.conf import settings
# import json
# import time
# from datetime import datetime

# def datetime_handler(x):
#     if isinstance(x, datetime):
#         return x.isoformat()
#     raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

# @csrf_exempt
# def get_conversations_customer(request):
#     def event_stream(user):
#         while True:
#             chats = Chat.objects.filter(
#                 service_provider_request__job_posting__user=user,
#                 status__in=['messaging', 'confirmed']
#             ).select_related('service_provider_request', 'service_provider_request__service_provider').annotate(
#                 unseen_count=Count('messages', filter=Q(messages__receiver=user, messages__seen=False))
#             )

#             conversations = []
#             for chat in chats:
#                 last_message = chat.messages.last()
#                 truncated_message = (last_message.message[:17] + '...') if last_message and len(last_message.message) > 17 else last_message.message if last_message else 'Tap to Start Conversation!'
#                 last_message_time = last_message.time.isoformat() if last_message else datetime.now().isoformat()
#                 conversations.append({
#                     'id': chat.id,
#                     'service_provider_request': {
#                         'id': chat.service_provider_request.id,
#                         'service_provider': {
#                             'first_name': chat.service_provider_request.service_provider.first_name,
#                             'last_name': chat.service_provider_request.service_provider.last_name,
#                         },
#                         'job_posting': {
#                             'service_type': chat.service_provider_request.job_posting.service_type,
#                         },
#                     },
#                     'last_message': {
#                         'message': truncated_message,
#                         'time': last_message_time,
#                     },
#                     'unseen_count': chat.unseen_count,
#                 })

#             # Sort: "Tap to Start Conversation!" at the top, then by last message time
#             conversations.sort(key=lambda x: (x['last_message']['message'] != 'Tap to Start Conversation!', x['last_message']['time']), reverse=True)
#             yield f'data: {json.dumps(conversations, default=datetime_handler)}\n\n'
#             time.sleep(2)  # Adjust the sleep time as needed

#     if request.method == 'GET':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token['user_id']
#             user = User.objects.get(id=user_id)
#             response = StreamingHttpResponse(event_stream(user), content_type='text/event-stream')
#             response['Cache-Control'] = 'no-cache'
#             return response
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ServiceProviderRequest, Chat, Message, User
import jwt
from django.conf import settings
import json
import time
from datetime import datetime
from django.db.models import Count, Q

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

@csrf_exempt
def get_conversations_customer(request):
    def event_stream(user):
        while True:
            chats = Chat.objects.filter(
                service_provider_request__job_posting__user=user,
                status__in=['messaging', 'confirmed']
            ).select_related('service_provider_request', 'service_provider_request__service_provider').annotate(
                unseen_count=Count('messages', filter=Q(messages__receiver=user, messages__seen=False))
            )

            conversations = []
            for chat in chats:
                last_message = chat.messages.last()
                truncated_message = (last_message.message[:17] + '...') if last_message and len(last_message.message) > 17 else last_message.message if last_message else 'Tap to Start Conversation!'
                last_message_time = last_message.time.isoformat() if last_message else datetime.now().isoformat()
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + chat.service_provider_request.service_provider.profile_photo) if chat.service_provider_request.service_provider.profile_photo else 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'
                conversations.append({
                    'id': chat.id,
                    'service_provider_request': {
                        'id': chat.service_provider_request.id,
                        'service_provider': {
                            'first_name': chat.service_provider_request.service_provider.first_name,
                            'last_name': chat.service_provider_request.service_provider.last_name,
                            'profile_photo': profile_photo_url,
                        },
                        'job_posting': {
                            'service_type': chat.service_provider_request.job_posting.service_type,
                        },
                    },
                    'last_message': {
                        'message': truncated_message,
                        'time': last_message_time,
                    },
                    'unseen_count': chat.unseen_count,
                })

            # Sort: "Tap to Start Conversation!" at the top, then by last message time
            conversations.sort(key=lambda x: (x['last_message']['message'] != 'Tap to Start Conversation!', x['last_message']['time']), reverse=True)
            yield f'data: {json.dumps(conversations, default=datetime_handler)}\n\n'
            time.sleep(2)  # Adjust the sleep time as needed

    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)
            response = StreamingHttpResponse(event_stream(user), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

# from django.db.models import Count, Q
# from django.http import JsonResponse, StreamingHttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import ServiceProviderRequest, Chat, Message, User
# import jwt
# from django.conf import settings
# import json
# import time
# from datetime import datetime

# def datetime_handler(x):
#     if isinstance(x, datetime):
#         return x.isoformat()
#     raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

# @csrf_exempt
# def get_conversations_service_provider(request):
#     def event_stream(user):
#         while True:
#             chats = Chat.objects.filter(
#                 service_provider_request__service_provider=user,
#                 status__in=['messaging', 'confirmed']
#             ).select_related('service_provider_request', 'service_provider_request__job_posting').annotate(
#                 unseen_count=Count('messages', filter=Q(messages__receiver=user, messages__seen=False))
#             )

#             conversations = []
#             for chat in chats:
#                 last_message = chat.messages.last()
#                 truncated_message = (last_message.message[:17] + '...') if last_message and len(last_message.message) > 17 else last_message.message if last_message else 'Tap to Start Conversation!'
#                 last_message_time = last_message.time.isoformat() if last_message else datetime.now().isoformat()
#                 conversations.append({
#                     'id': chat.id,
#                     'service_provider_request': {
#                         'id': chat.service_provider_request.id,
#                         'job_posting': {
#                             'service_type': chat.service_provider_request.job_posting.service_type,
#                             'user': {
#                                 'first_name': chat.service_provider_request.job_posting.user.first_name,
#                                 'last_name': chat.service_provider_request.job_posting.user.last_name,
#                             }
#                         },
#                         'service_provider': {
#                             'first_name': chat.service_provider_request.service_provider.first_name,
#                             'last_name': chat.service_provider_request.service_provider.last_name,
#                         }
#                     },
#                     'last_message': {
#                         'message': truncated_message,
#                         'time': last_message_time,
#                     },
#                     'unseen_count': chat.unseen_count,
#                 })

#             # Sort: "Tap to Start Conversation!" at the top, then by last message time
#             conversations.sort(key=lambda x: (x['last_message']['message'] != 'Tap to Start Conversation!', x['last_message']['time']), reverse=True)
#             yield f'data: {json.dumps(conversations, default=datetime_handler)}\n\n'
#             time.sleep(2)  # Adjust the sleep time as needed

#     if request.method == 'GET':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token['user_id']
#             user = User.objects.get(id=user_id)
#             response = StreamingHttpResponse(event_stream(user), content_type='text/event-stream')
#             response['Cache-Control'] = 'no-cache'
#             return response
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)
from django.db.models import Count, Q
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ServiceProviderRequest, Chat, Message, User
import jwt
from django.conf import settings
import json
import time
from datetime import datetime

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

@csrf_exempt
def get_conversations_service_provider(request):
    def event_stream(user):
        while True:
            chats = Chat.objects.filter(
                service_provider_request__service_provider=user,
                status__in=['messaging', 'confirmed']
            ).select_related('service_provider_request', 'service_provider_request__job_posting', 'service_provider_request__job_posting__user').annotate(
                unseen_count=Count('messages', filter=Q(messages__receiver=user, messages__seen=False))
            )

            conversations = []
            for chat in chats:
                last_message = chat.messages.last()
                truncated_message = (last_message.message[:17] + '...') if last_message and len(last_message.message) > 17 else last_message.message if last_message else 'Tap to Start Conversation!'
                last_message_time = last_message.time.isoformat() if last_message else datetime.now().isoformat()
                
                job_posting_user = chat.service_provider_request.job_posting.user
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + job_posting_user.profile_photo) if job_posting_user.profile_photo else 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'
                
                conversations.append({
                    'id': chat.id,
                    'service_provider_request': {
                        'id': chat.service_provider_request.id,
                        'job_posting': {
                            'service_type': chat.service_provider_request.job_posting.service_type,
                            'user': {
                                'first_name': job_posting_user.first_name,
                                'last_name': job_posting_user.last_name,
                                'profile_photo': profile_photo_url,
                            }
                        },
                        'service_provider': {
                            'first_name': chat.service_provider_request.service_provider.first_name,
                            'last_name': chat.service_provider_request.service_provider.last_name,
                        }
                    },
                    'last_message': {
                        'message': truncated_message,
                        'time': last_message_time,
                    },
                    'unseen_count': chat.unseen_count,
                })

            # Sort: "Tap to Start Conversation!" at the top, then by last message time
            conversations.sort(key=lambda x: (x['last_message']['message'] != 'Tap to Start Conversation!', x['last_message']['time']), reverse=True)
            yield f'data: {json.dumps(conversations, default=datetime_handler)}\n\n'
            time.sleep(2)  # Adjust the sleep time as needed

    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)
            response = StreamingHttpResponse(event_stream(user), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)


# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import Chat, User
# import jwt
# from django.conf import settings

# @csrf_exempt
# def delete_chat(request, chat_id):
#     if request.method == 'DELETE':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token['user_id']
#             user = User.objects.get(id=user_id)

#             chat = get_object_or_404(Chat, id=chat_id, service_provider_request__job_posting__user=user)
#             chat.status = 'deleted'
#             chat.save()

#             return JsonResponse({'message': 'Chat deleted successfully!'}, status=200)
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)

from django.db import transaction

@csrf_exempt
def delete_chat(request, chat_id):
    if request.method == 'DELETE':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            with transaction.atomic():
                chat = get_object_or_404(Chat, id=chat_id, service_provider_request__job_posting__user=user)
                chat.status = 'deleted'
                chat.save()

                # Update the job posting's status or remove it from the upcoming trips list
                job_posting = chat.service_provider_request.job_posting
                job_posting.status = 'closed'  # Example status update, modify as per your logic
                job_posting.save()

            return JsonResponse({'message': 'Chat deleted successfully!'}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)



from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, Message, User
import jwt
from django.conf import settings
import json
from django.utils import timezone
import time


@csrf_exempt
def live_data_stream(request):
    def live_module_stream():
        while True:
            messages = Message.objects.all().order_by('time')
            message_list = [
                {
                    'id': msg.id,
                    'chat_id': msg.chat.id,
                    'sender': msg.sender.first_name,
                    'message': msg.message,
                    'time': msg.time.isoformat(),
                    'isUserMessage': msg.sender.id == request.user.id if request.user.is_authenticated else False
                }
                for msg in messages
            ]
            yield f"data: {json.dumps(message_list)}\n\n"
            time.sleep(1)
    return StreamingHttpResponse(live_module_stream(), content_type='text/event-stream')

@csrf_exempt
def send_message_customer(request):
    if request.method == 'POST':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            data = json.loads(request.body)
            chat_id = data.get('chat_id')
            message_text = data.get('message')

            chat = Chat.objects.get(id=chat_id)
            service_provider_request = chat.service_provider_request

            if user == service_provider_request.service_provider:
                receiver = service_provider_request.job_posting.user
            else:
                receiver = service_provider_request.service_provider

            Message.objects.create(
                chat=chat,
                sender=user,
                receiver=receiver,
                message=message_text,
                time=timezone.now()
            )

            return JsonResponse({'message': 'Message sent successfully!'}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Chat.DoesNotExist:
            return JsonResponse({'message': 'Chat not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)


from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, Message, User
import jwt
from django.conf import settings
import json
from django.utils import timezone
import time


def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

@csrf_exempt
def get_messages_service_provider(request, chat_id):
    def event_stream(user, chat_id):
        while True:
            chat = Chat.objects.get(id=chat_id)
            messages = Message.objects.filter(chat=chat).order_by('time')
            
            # Mark messages as seen
            messages.filter(receiver=user, seen=False).update(seen=True)

            messages_data = [
                {
                    'id': msg.id,
                    'sender': msg.sender.first_name,
                    'message': msg.message,
                    'time': msg.time.isoformat(),
                    'isUserMessage': msg.sender.id == user.id
                }
                for msg in messages
            ]
            yield f"data: {json.dumps(messages_data, default=datetime_handler)}\n\n"
            time.sleep(1)

    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)
            response = StreamingHttpResponse(event_stream(user, chat_id), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Chat.DoesNotExist:
            return JsonResponse({'message': 'Chat not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)
@csrf_exempt
def send_message_service_provider(request):
    if request.method == 'POST':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            data = json.loads(request.body)
            chat_id = data.get('chat_id')
            message_text = data.get('message')

            chat = Chat.objects.get(id=chat_id)
            service_provider_request = chat.service_provider_request

            # Determine the receiver correctly
            if user == service_provider_request.service_provider:
                receiver = service_provider_request.job_posting.user
            else:
                receiver = service_provider_request.service_provider

            Message.objects.create(
                chat=chat,
                sender=user,
                receiver=receiver,
                message=message_text,
                time=timezone.now()
            )

            return JsonResponse({'message': 'Message sent successfully!'}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Chat.DoesNotExist:
            return JsonResponse({'message': 'Chat not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)







# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import Chat, User
# import jwt
# from django.conf import settings

# @csrf_exempt
# def trip_info(request, chat_id):
#     if request.method == 'GET':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token['user_id']
#             user = User.objects.get(id=user_id)

#             chat = get_object_or_404(Chat, id=chat_id)
#             trip = chat.service_provider_request.job_posting
#             driver = chat.service_provider_request.service_provider
#             service_provider_profile = driver.service_providers.first()  # Assuming a ServiceProvider model exists

#             # Construct the profile photo URL
#             profile_photo_url = None
#             if driver.profile_photo:
#                 profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + driver.profile_photo)

#             trip_info = {
#                 'id': trip.id,
#                 'service_type': trip.service_type,
#                 'service_period': trip.service_period,
#                 'service_rate': trip.service_rate,
#                 'onboarding_location': trip.onboarding_location,
#                 'job_summary': trip.job_summary,
#             }

#             driver_info = {
#                 'first_name': driver.first_name,
#                 'last_name': driver.last_name,
#                 'email': driver.email,
#                 'phone': driver.phone,
#                 'rating': driver.rating,
#                 'years_in_industry': service_provider_profile.years_in_industry if service_provider_profile else None,
#                 'vehicle_type': driver.driver.vehicle_type if hasattr(driver, 'driver') else None,
#                 'app_verified_date': service_provider_profile.app_verified_date if service_provider_profile else None,
#                 'profile_photo': profile_photo_url,  # Include the profile photo URL here
#             }

#             return JsonResponse({'trip': trip_info, 'driver': driver_info}, status=200)
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, User
import jwt
from django.conf import settings

@csrf_exempt
def trip_info(request, chat_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = get_object_or_404(User, id=user_id)

            chat = get_object_or_404(Chat, id=chat_id)
            service_provider_request = chat.service_provider_request
            trip = service_provider_request.job_posting
            driver = service_provider_request.service_provider
            service_provider_profile = driver.service_providers.first()

            # Check if trip or driver info is missing
            if not trip or not driver:
                return JsonResponse({'message': 'Trip or driver information is missing.'}, status=404)

            # Construct the profile photo URL
            profile_photo_url = None
            if driver.profile_photo:
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + driver.profile_photo)

            trip_info = {
                'id': trip.id,
                'service_type': trip.service_type,
                'service_period': trip.service_period,
                'service_rate': trip.service_rate,
                'onboarding_location': trip.onboarding_location,
                'job_summary': trip.job_summary,
                'status': trip.status,  # Include trip status
            }

            driver_info = {
                'first_name': driver.first_name,
                'last_name': driver.last_name,
                'email': driver.email,
                'phone': driver.phone,
                'rating': driver.rating,
                'years_in_industry': service_provider_profile.years_in_industry if service_provider_profile else None,
                'vehicle_type': driver.driver.vehicle_type if hasattr(driver, 'driver') else None,
                'app_verified_date': service_provider_profile.app_verified_date if service_provider_profile else None,
                'profile_photo': profile_photo_url,  # Include the profile photo URL here
            }

            return JsonResponse({'trip': trip_info, 'driver': driver_info}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, User
import jwt
from django.conf import settings
from django.templatetags.static import static

@csrf_exempt
def trip_info_serviceprovider(request, chat_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            chat = get_object_or_404(Chat, id=chat_id)
            trip = chat.service_provider_request.job_posting
            customer = trip.user  # Fetch the customer associated with the job posting

            # Ensure the profile photo is correctly formatted as a URL
            profile_photo_url = None
            if customer.profile_photo:
                profile_photo_url = f"{settings.MEDIA_URL}{customer.profile_photo}"
            
            trip_info = {
                'id': trip.id,
                'service_type': trip.service_type,
                'service_period': trip.service_period,
                'service_rate': trip.service_rate,
                'onboarding_location': trip.onboarding_location,
                'job_summary': trip.job_summary,
            }

            customer_info = {
                'first_name': customer.first_name,
                'last_name': customer.last_name,
                'email': customer.email,
                'phone': customer.phone,
                'rating': customer.rating if customer.rating is not None else 5,
                'profile_photo': profile_photo_url,
            }

            return JsonResponse({'trip': trip_info, 'customer': customer_info}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)


from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import JobPosting
import jwt
import json
import time

def job_postings_stream():
    while True:
        job_postings = JobPosting.objects.all().order_by('-created_at')
        data = [
            {
                'id': job.id,
                'service_type': job.service_type,
                'service_period': job.service_period,
                'service_rate': job.service_rate,
                'onboarding_location': job.onboarding_location,
                'job_summary': job.job_summary,
            }
            for job in job_postings
        ]
        yield f"data: {json.dumps(data)}\n\n"
        time.sleep(2)  # Adjust the sleep time as needed

@csrf_exempt
def job_postings_sse(request):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            response = StreamingHttpResponse(job_postings_stream(), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)



# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse, StreamingHttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import ServiceProviderRequest, User, JobPosting, Driver, ServiceProvider
# import jwt
# from django.conf import settings
# import json
# import time
# from datetime import datetime, timezone

# def datetime_handler(x):
#     if isinstance(x, datetime):
#         return x.isoformat()
#     raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

# def get_days_ago(time):
#     now = datetime.now(timezone.utc)
#     diff = now - time
#     days = diff.days
#     return f"{days} days ago" if days > 0 else "Today"

# def get_driver_requests_stream(user):
#     while True:
#         job_postings = JobPosting.objects.filter(user=user)
#         requests = ServiceProviderRequest.objects.filter(job_posting__in=job_postings).select_related('job_posting', 'service_provider')
        
#         data = []
#         for request in requests:
#             service_provider = request.service_provider
#             driver = Driver.objects.filter(user=service_provider).first()
#             service_provider_instance = ServiceProvider.objects.filter(user=service_provider).first()

#             service_provider_data = {
#                 'service_provider_id': service_provider.id,
#                 'service_provider_name': f"{service_provider.first_name} {service_provider.last_name}",
#                 'service_provider_rating': service_provider.rating,
#                 'years_in_industry': service_provider_instance.years_in_industry if service_provider_instance else None,
#                 'vehicle_type': driver.vehicle_type if driver else None,
#             }
#             request_data = {
#                 'id': request.id,
#                 'job_posting_id': request.job_posting.id,
#                 'job_posting_summary': request.job_posting.job_summary,
#                 'request_status': request.request_status,
#                 'sent_request_time': get_days_ago(request.sent_request_time),
#                 **service_provider_data,
#             }
#             data.append(request_data)
        
#         yield f'data: {json.dumps(data, default=datetime_handler)}\n\n'
#         time.sleep(2)

# @csrf_exempt
# def get_driver_requests(request):
#     if request.method == 'GET':
#         token = request.GET.get('token', None)
#         if not token:
#             return JsonResponse({'message': 'Token not provided'}, status=403)
#         try:
#             decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded['user_id']
#             user = User.objects.get(id=user_id)
            
#             response = StreamingHttpResponse(get_driver_requests_stream(user), content_type='text/event-stream')
#             response['Cache-Control'] = 'no-cache'
#             return response
        
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ServiceProviderRequest, User, JobPosting, ServiceProvider, Driver
import jwt
from django.conf import settings
import json
import time
from datetime import datetime, timezone

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError(f"Object of type {x.__class__.__name__} is not JSON serializable")

def get_days_ago(time):
    now = datetime.now(timezone.utc)
    diff = now - time
    days = diff.days
    return f"{days} days ago" if days > 0 else "Today"

def get_driver_requests_stream(user, request):
    while True:
        job_postings = JobPosting.objects.filter(user=user)
        requests = ServiceProviderRequest.objects.filter(job_posting__in=job_postings).select_related('job_posting', 'service_provider')
        
        data = []
        for req in requests:
            service_provider = req.service_provider
            service_provider_instance = ServiceProvider.objects.filter(user=service_provider).first()
            if service_provider.profile_photo:
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + service_provider.profile_photo)
            else:
                profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'
                
            service_provider_data = {
                'service_provider_id': service_provider.id,
                'service_provider_name': f"{service_provider.first_name} {service_provider.last_name}",
                'service_provider_rating': service_provider.rating,
                'years_in_industry': service_provider_instance.years_in_industry if service_provider_instance else None,
                'vehicle_type': service_provider_instance.driver.vehicle_type if service_provider_instance and hasattr(service_provider_instance, 'driver') else None,
                'service_provider_photo': profile_photo_url,
            }
            request_data = {
                'id': req.id,
                'job_posting_id': req.job_posting.id,
                'job_posting_summary': req.job_posting.job_summary,
                'request_status': req.request_status,
                'sent_request_time': get_days_ago(req.sent_request_time),
                **service_provider_data,
            }
            data.append(request_data)
        
        yield f'data: {json.dumps(data, default=datetime_handler)}\n\n'
        time.sleep(2)

@csrf_exempt
def get_driver_requests(request):
    if request.method == 'GET':
        token = request.GET.get('token', None)
        if not token:
            return JsonResponse({'message': 'Token not provided'}, status=403)
        try:
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded['user_id']
            user = User.objects.get(id=user_id)
            
            response = StreamingHttpResponse(get_driver_requests_stream(user, request), content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            return response
        
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)


# Assuming you have this function for decoding JWT token
def decode_jwt(token):
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import JobPosting, ServiceProviderRequest
from .serializers import JobPostingSerializer
import jwt
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class RequestedJobPostingsView(APIView):
    def get(self, request, *args, **kwargs):
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')

            requested_jobs = JobPosting.objects.filter(
                service_provider_requests__service_provider_id=user_id,
                service_provider_requests__request_status='send_request'
            ).distinct().order_by('-service_provider_requests__sent_request_time')

            serializer = JobPostingSerializer(requested_jobs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            logger.error('Token has expired')
            return Response({'message': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            logger.error('Invalid token')
            return Response({'message': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# views.py

# from django.utils.decorators import method_decorator
# from django.views import View
# from django.views.decorators.csrf import csrf_exempt
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User, Driver, Maid, JobPosting
# import jwt
# import json
# from django.conf import settings
# from django.http import JsonResponse

# def decode_jwt(token):
#     try:
#         decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#         if 'user_id' not in decoded_token:
#             return {'error': 'Token is missing user_id'}
#         return decoded_token
#     except jwt.ExpiredSignatureError:
#         return {'error': 'Token has expired'}
#     except jwt.InvalidTokenError:
#         return {'error': 'Invalid token'}

# @csrf_exempt
# @api_view(['GET'])
# def get_relevant_job_postings(request):
#     token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#     decoded = decode_jwt(token)

#     if 'error' in decoded:
#         return JsonResponse({'message': decoded['error']}, status=403)

#     user_id = decoded['user_id']
    
#     try:
#         user = User.objects.get(id=user_id)
#     except User.DoesNotExist:
#         return JsonResponse({'message': 'User not found'}, status=404)

#     if hasattr(user, 'driver'):
#         service_type = 'Driver'
#     elif hasattr(user, 'maid'):
#         service_type = 'Maid'
#     else:
#         return JsonResponse({'message': 'User is not a service provider.'}, status=403)

#     job_postings = JobPosting.objects.filter(service_type=service_type)
#     data = [
#         {
#             'id': job_posting.id,
#             'service_type': job_posting.service_type,
#             'service_period': job_posting.service_period,
#             'service_rate': job_posting.service_rate,
#             'onboarding_location': job_posting.onboarding_location,
#             'job_summary': job_posting.job_summary,
#             'status': job_posting.status,
#             'created_at': job_posting.created_at,
#             'updated_at': job_posting.updated_at,
#         }
#         for job_posting in job_postings
#     ]
#     return JsonResponse(data, safe=False, status=200)
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import User, Driver, Maid, JobPosting, AcceptedRequest, Chat, ServiceProviderRequest
import jwt
import json
from django.conf import settings
from django.http import JsonResponse

def decode_jwt(token):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}

@csrf_exempt
@api_view(['GET'])
def get_relevant_job_postings(request):
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    decoded = decode_jwt(token)

    if 'error' in decoded:
        return JsonResponse({'message': decoded['error']}, status=403)

    user_id = decoded['user_id']
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found'}, status=404)

    if hasattr(user, 'driver'):
        service_type = 'Driver'
    elif hasattr(user, 'maid'):
        service_type = 'Maid'
    else:
        return JsonResponse({'message': 'User is not a service provider.'}, status=403)

    # Get job postings associated with accepted requests
    accepted_requests = AcceptedRequest.objects.values_list('service_provider_request__job_posting', flat=True)

    # Get job postings associated with service provider requests in the Chat table
    chat_requests = Chat.objects.values_list('service_provider_request__job_posting', flat=True)

    # Get service provider requests related to the user, excluding rejected ones
    user_requests = ServiceProviderRequest.objects.filter(service_provider=user).exclude(request_status='rejected').values('job_posting_id', 'request_status')

    # Create a dictionary to map job posting IDs to their request statuses
    request_status_map = {request['job_posting_id']: request['request_status'] for request in user_requests}

    # Exclude job postings associated with accepted requests, chat requests, and those with a rejected request status
    rejected_requests = ServiceProviderRequest.objects.filter(service_provider=user, request_status='rejected').values_list('job_posting_id', flat=True)
    job_postings = JobPosting.objects.filter(service_type=service_type).exclude(id__in=accepted_requests).exclude(id__in=chat_requests).exclude(id__in=rejected_requests)
    
    data = [
        {
            'id': job_posting.id,
            'service_type': job_posting.service_type,
            'service_period': job_posting.service_period,
            'service_rate': job_posting.service_rate,
            'onboarding_location': job_posting.onboarding_location,
            'job_summary': job_posting.job_summary,
            'status': job_posting.status,
            'created_at': job_posting.created_at,
            'updated_at': job_posting.updated_at,
            'request_status': request_status_map.get(job_posting.id, None)
        }
        for job_posting in job_postings
    ]
    return JsonResponse(data, safe=False, status=200)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ServiceProviderRequest, JobPosting, User
from .serializers import ServiceProviderRequestSerializer
import jwt
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class ServiceProviderRequestView(APIView):
    def post(self, request, *args, **kwargs):
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')

            job_posting_id = request.data.get('job_posting_id')
            action = request.data.get('action')

            if not all([job_posting_id, action]):
                return Response({'error': 'All fields (job_posting_id, action) are required.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                job_posting = JobPosting.objects.get(id=job_posting_id)
                service_provider = User.objects.get(id=user_id)
            except JobPosting.DoesNotExist:
                return Response({'error': 'Job posting not found.'}, status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

            if action not in ['send_request', 'unsend_request']:
                return Response({'error': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)

            service_provider_request, created = ServiceProviderRequest.objects.get_or_create(
                job_posting=job_posting,
                service_provider=service_provider,
                defaults={'request_status': 'pending'}
            )

            if action == 'send_request':
                service_provider_request.request_status = 'send_request'
                service_provider_request.sent_request_time = timezone.now()
            elif action == 'unsend_request':
                service_provider_request.request_status = 'pending'
                service_provider_request.sent_request_time = None

            service_provider_request.save()

            serializer = ServiceProviderRequestSerializer(service_provider_request)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            logger.error('Token has expired')
            return Response({'message': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            logger.error('Invalid token')
            return Response({'message': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')

            job_posting_id = request.query_params.get('job_posting_id')

            if not job_posting_id:
                return Response({'error': 'job_posting_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                job_posting = JobPosting.objects.get(id=job_posting_id)
                service_provider = User.objects.get(id=user_id)
                service_provider_request = ServiceProviderRequest.objects.filter(
                    job_posting=job_posting,
                    service_provider=service_provider
                ).first()
                
                if service_provider_request:
                    serializer = ServiceProviderRequestSerializer(service_provider_request)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'No request found for this job posting.'}, status=status.HTTP_404_NOT_FOUND)
            except JobPosting.DoesNotExist:
                return Response({'error': 'Job posting not found.'}, status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        except jwt.ExpiredSignatureError:
            logger.error('Token has expired')
            return Response({'message': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            logger.error('Invalid token')
            return Response({'message': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import ServiceProviderRequest
from django.views.decorators.csrf import csrf_exempt
import jwt
from django.conf import settings

# @csrf_exempt
# def request_details(request, request_id):
#     if request.method == 'GET':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token.get('user_id')

#             service_provider_request = get_object_or_404(ServiceProviderRequest, id=request_id, job_posting__user_id=user_id)
#             service_provider = service_provider_request.service_provider
#             service_provider_profile = service_provider.service_providers.first()

#             request_details = {
#                 'id': service_provider_request.id,
#                 'service_provider': {
#                     'first_name': service_provider.first_name,
#                     'last_name': service_provider.last_name,
#                     'rating': service_provider.rating,
#                     'years_in_industry': service_provider_profile.years_in_industry if service_provider_profile else None,
#                     'vehicle_type': service_provider.driver.vehicle_type if hasattr(service_provider, 'driver') else None,
#                     'app_verified_date': service_provider_profile.app_verified_date if service_provider_profile else None,
#                 },
#                 'job_posting': {
#                     'id': service_provider_request.job_posting.id,
#                     'service_type': service_provider_request.job_posting.service_type,
#                     'service_period': service_provider_request.job_posting.service_period,
#                     'service_rate': service_provider_request.job_posting.service_rate,
#                     'onboarding_location': service_provider_request.job_posting.onboarding_location,
#                     'job_summary': service_provider_request.job_posting.job_summary,
#                 },
#                 'sent_request_time': service_provider_request.sent_request_time,
#             }

#             return JsonResponse(request_details, safe=False, status=200)
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except ServiceProviderRequest.DoesNotExist:
#             return JsonResponse({'message': 'Request not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         return JsonResponse({'message': 'Invalid request method'}, status=405)


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import ServiceProviderRequest
from django.views.decorators.csrf import csrf_exempt
import jwt
from django.conf import settings

@csrf_exempt
def request_details(request, request_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token.get('user_id')

            service_provider_request = get_object_or_404(ServiceProviderRequest, id=request_id, job_posting__user_id=user_id)
            service_provider = service_provider_request.service_provider
            service_provider_profile = service_provider.service_providers.first()

            profile_photo_url = service_provider.profile_photo
            if profile_photo_url:
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + profile_photo_url)
            else:
                profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

            request_details = {
                'id': service_provider_request.id,
                'service_provider': {
                    'first_name': service_provider.first_name,
                    'last_name': service_provider.last_name,
                    'rating': service_provider.rating,
                    'years_in_industry': service_provider_profile.years_in_industry if service_provider_profile else None,
                    'vehicle_type': service_provider.driver.vehicle_type if hasattr(service_provider, 'driver') else None,
                    'app_verified_date': service_provider_profile.app_verified_date if service_provider_profile else None,
                    'profile_photo': profile_photo_url,  # Include the profile photo URL here
                },
                'job_posting': {
                    'id': service_provider_request.job_posting.id,
                    'service_type': service_provider_request.job_posting.service_type,
                    'service_period': service_provider_request.job_posting.service_period,
                    'service_rate': service_provider_request.job_posting.service_rate,
                    'onboarding_location': service_provider_request.job_posting.onboarding_location,
                    'job_summary': service_provider_request.job_posting.job_summary,
                },
                'sent_request_time': service_provider_request.sent_request_time,
            }

            return JsonResponse(request_details, safe=False, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except ServiceProviderRequest.DoesNotExist:
            return JsonResponse({'message': 'Request not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

import logging
import os
import uuid
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from .models import User

logger = logging.getLogger(__name__)

@csrf_exempt
@require_POST
def upload_profile_photo_serviceprovider(request):
    try:
        logger.debug("Received upload profile photo request")
        
        user_id = request.POST.get('user_id')
        logger.debug(f"User ID: {user_id}")

        if not user_id:
            logger.error("User ID not provided")
            return JsonResponse({'status': 'error', 'message': 'User ID not provided'})

        user = get_object_or_404(User, id=user_id)
        logger.debug(f"User found: {user}")

        profile_photo = request.FILES.get('profile_photo')
        logger.debug(f"Profile photo received: {profile_photo}")

        if not profile_photo:
            logger.error("No file uploaded")
            return JsonResponse({'status': 'error', 'message': 'No file uploaded'})

        # Generate a unique filename
        ext = profile_photo.name.split('.')[-1]
        unique_filename = f"{uuid.uuid4()}.{ext}"
        profile_photo.name = unique_filename
        logger.debug(f"Unique filename: {unique_filename}")

        # Save the new profile photo
        file_path = os.path.join(settings.MEDIA_ROOT, 'users', 'images', 'profilepic')
        fs = FileSystemStorage(location=file_path)
        filename = fs.save(profile_photo.name, profile_photo)
        logger.debug(f"Profile photo saved at: {fs.path(filename)}")

        # Store the previous photo path for deletion
        previous_photo_path = os.path.join(settings.MEDIA_ROOT, user.profile_photo) if user.profile_photo else None

        # Update user's profile photo path in the database
        user.profile_photo = os.path.join('users', 'images', 'profilepic', filename)

        # Attempt to save user with the new profile photo
        try:
            user.save()
        except Exception as save_error:
            logger.error(f"Failed to update user profile with new photo: {save_error}")
            # Remove the newly saved photo if user save failed
            if os.path.isfile(fs.path(filename)):
                os.remove(fs.path(filename))
            return JsonResponse({'status': 'error', 'message': 'Failed to update user profile with new photo'})

        # If no error, delete the previous profile photo
        if previous_photo_path and os.path.isfile(previous_photo_path):
            try:
                logger.debug(f"Removing old profile photo: {previous_photo_path}")
                os.remove(previous_photo_path)
            except Exception as delete_error:
                logger.error(f"Failed to delete old profile photo {previous_photo_path}: {delete_error}")

        return JsonResponse({'status': 'success', 'profile_photo_url': request.build_absolute_uri(os.path.join(settings.MEDIA_URL, user.profile_photo))})
    except Exception as e:
        logger.error(f"An error occurred while uploading the profile photo: {e}")
        return JsonResponse({'status': 'error', 'message': f'An error occurred while uploading the profile photo: {e}'})

from django.http import JsonResponse
from django.conf import settings
from rest_framework.decorators import api_view
import jwt
from .models import User
import logging

logger = logging.getLogger(__name__)

@api_view(['GET'])
def service_provider_profile_view(request):
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded.get('user_id')
        if not user_id:
            return JsonResponse({'message': 'Invalid token payload'}, status=401)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)

        if user.profile_photo:
            profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + user.profile_photo)
        else:
            profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            'rating': user.rating,
            'nid': user.nid,
            'date_of_birth': user.date_of_birth,
            'updated_at': user.updated_at,
            'profile_photo': profile_photo_url,
        }
        return JsonResponse({'user': user_data}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    except Exception as e:
        logger.error(f"Error fetching profile: {e}")
        return JsonResponse({'message': 'An error occurred while fetching profile'}, status=500)

from django.views.decorators.http import require_POST
from django.db.models import Q
from django.http import JsonResponse
from .models import Message

@require_POST
@csrf_exempt
def mark_messages_as_seen(request, conversation_id):
    try:
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['user_id']
        user = User.objects.get(id=user_id)
        
        messages = Message.objects.filter(chat_id=conversation_id, receiver=user, seen=False)
        messages.update(seen=True)
        
        return JsonResponse({'message': 'Messages marked as seen'}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)

from django.http import JsonResponse
from django.conf import settings
from rest_framework.decorators import api_view
import jwt
from .models import User, Customer
import logging

logger = logging.getLogger(__name__)


# @api_view(['GET', 'PUT'])
# def profile_view_customer(request):
#     token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#     try:
#         decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#         user_id = decoded.get('user_id')
#         if not user_id:
#             return JsonResponse({'message': 'Invalid token payload'}, status=401)
        
#         try:
#             user = User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
        
#         try:
#             customer = Customer.objects.get(user=user)
#         except Customer.DoesNotExist:
#             return JsonResponse({'message': 'Customer profile not found'}, status=404)

#         if request.method == 'GET':
#             # existing GET logic
#             if user.profile_photo:
#                 profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + user.profile_photo)
#                 logger.info(f"Profile Photo URL: {profile_photo_url}")
#             else:
#                 profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

#             user_data = {
#                 'id': user.id,
#                 'first_name': user.first_name,
#                 'last_name': user.last_name,
#                 'email': user.email,
#                 'phone': user.phone,
#                 'address': user.address,
#                 'occupation': customer.occupation,
#                 'rating': customer.rating,
#                 'nid': user.nid,
#                 'date_of_birth': user.date_of_birth,
#                 'profile_photo': profile_photo_url,
#             }
#             return JsonResponse({'user': user_data}, status=200)
        
#         elif request.method == 'PUT':
#             data = request.data
#             if 'occupation' in data:
#                 customer.occupation = data['occupation']
#                 customer.save()
            
#             if 'phone' in data:
#                 # Validate phone number if needed
#                 phone = data['phone']
#                 if phone.startswith('+880') and len(phone) == 14 and phone[4:].isdigit():
#                     user.phone = phone
#                     user.save()
#                 else:
#                     return JsonResponse({'message': 'Invalid phone number format'}, status=400)
            
#             return JsonResponse({'message': 'Profile updated successfully'}, status=200)

#     except jwt.ExpiredSignatureError:
#         return JsonResponse({'message': 'Token has expired'}, status=401)
#     except jwt.InvalidTokenError:
#         return JsonResponse({'message': 'Invalid token'}, status=401)
#     except Exception as e:
#         logger.error(f"Error fetching or updating profile: {e}")
#         return JsonResponse({'message': 'An error occurred while fetching or updating the profile'}, status=500)
@api_view(['GET', 'PUT'])
def profile_view_customer(request):
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded.get('user_id')
        if not user_id:
            return JsonResponse({'message': 'Invalid token payload'}, status=401)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        
        try:
            customer = Customer.objects.get(user=user)
        except Customer.DoesNotExist:
            return JsonResponse({'message': 'Customer profile not found'}, status=404)

        if request.method == 'GET':
            # existing GET logic
            if user.profile_photo:
                profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + user.profile_photo)
                logger.info(f"Profile Photo URL: {profile_photo_url}")
            else:
                profile_photo_url = 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

            user_data = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'phone': user.phone,
                'address': user.address,
                'occupation': customer.occupation,
                'rating': customer.rating,
                'nid': user.nid,
                'date_of_birth': user.date_of_birth,
                'profile_photo': profile_photo_url,
            }
            return JsonResponse({'user': user_data}, status=200)
        
        elif request.method == 'PUT':
            data = request.data
            if 'occupation' in data:
                customer.occupation = data['occupation']
                customer.save()

            if 'address' in data:
                user.address = data['address']
                user.save()
            
            if 'phone' in data:
                # Validate phone number if needed
                phone = data['phone']
                if phone.startswith('+880') and len(phone) == 14 and phone[4:].isdigit():
                    user.phone = phone
                    user.save()
                else:
                    return JsonResponse({'message': 'Invalid phone number format'}, status=400)
            
            return JsonResponse({'message': 'Profile updated successfully'}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    except Exception as e:
        logger.error(f"Error fetching or updating profile: {e}")
        return JsonResponse({'message': 'An error occurred while fetching or updating the profile'}, status=500)


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Chat, JobPosting, Transaction, Hiring, User
import jwt
from django.conf import settings
from django.db import transaction

@csrf_exempt
def book_trip(request, chat_id):
    if request.method == 'POST':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = get_object_or_404(User, id=user_id)
            chat = get_object_or_404(Chat, id=chat_id)

            service_provider_request = chat.service_provider_request
            job_posting = service_provider_request.job_posting

            # Check if the job posting is already closed
            if job_posting.status == 'closed':
                return JsonResponse({'message': 'This job posting is already closed and cannot be booked.'}, status=400)

            driver = service_provider_request.service_provider

            with transaction.atomic():
                # Close the job posting
                job_posting.status = 'closed'
                job_posting.save()
                print("Job posting closed")

                # Confirm the chat status
                chat.status = 'confirmed'
                chat.save()
                print("Chat status confirmed")

                # Create a new transaction linked to the job posting
                transaction_record = Transaction.objects.create(
                    job_posting=job_posting,
                    user=user,
                    hired_by=driver,
                    rate=job_posting.service_rate,
                    payment_method='card',
                    additional_info=None
                )
                print("Transaction created and linked to job posting")

                # Create a new hiring record linked to the transaction
                Hiring.objects.create(
                    customer=user,
                    service_provider=driver,
                    customer_rating=None,  # Null initially
                    service_provider_rating=None,  # Null initially
                    transaction=transaction_record
                )
                print("Hiring record created")

            return JsonResponse({'message': 'Booking confirmed successfully!'}, status=200)
        
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

# import logging
# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import Chat, JobPosting, Transaction, Hiring, User
# import jwt
# from django.conf import settings
# from django.db import transaction
# from datetime import datetime
# from django.utils import timezone

# # Configure logging
# logging.basicConfig(level=logging.DEBUG)
# logger = logging.getLogger(__name__)

# @csrf_exempt
# def user_trips_view(request):
#     if request.method == 'GET':
#         token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         try:
#             decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             user_id = decoded_token['user_id']
#             user = User.objects.get(id=user_id)

#             logger.debug(f"User ID: {user_id} - {user.email} is requesting their trips")

#             # Get all confirmed hirings for the user
#             confirmed_trips = Hiring.objects.filter(customer=user).select_related('service_provider', 'transaction', 'transaction__job_posting')
#             logger.debug(f"Total confirmed trips: {confirmed_trips.count()}")

#             upcoming_trips = []
#             past_trips = []
#             current_time = timezone.now().date()

#             for trip in confirmed_trips:
#                 job_posting = trip.transaction.job_posting

#                 if job_posting and job_posting.service_period:
#                     service_period_str = job_posting.service_period  # Example: '2024-08-17 - 2024-08-25'
#                     service_period_start_str, service_period_end_str = service_period_str.split(' - ')

#                     service_period_start = datetime.strptime(service_period_start_str, '%Y-%m-%d').date()
#                     service_period_end = datetime.strptime(service_period_end_str, '%Y-%m-%d').date()

#                     profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + trip.service_provider.profile_photo) if trip.service_provider.profile_photo else 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

#                     trip_info = {
#                         'id': trip.id,
#                         'driverProfilePic': profile_photo_url,
#                         'driverName': f"{trip.service_provider.first_name} {trip.service_provider.last_name}",
#                         'serviceProviderType': job_posting.service_type,
#                         'serviceRate': trip.transaction.rate,
#                         'servicePeriodStart': service_period_start_str,
#                         'servicePeriodEnd': service_period_end_str,
#                         'tripId': trip.id,
#                         'transactionId': trip.transaction.id,
#                         'jobPostingId': job_posting.id,
#                     }

#                     # Log trip details for debugging
#                     logger.debug(f"Processing Trip: {trip_info}")

#                     if service_period_end >= current_time:
#                         days_to_go = (service_period_end - current_time).days
#                         trip_info['daysToGo'] = days_to_go
#                         upcoming_trips.append(trip_info)
#                         logger.debug(f"Upcoming Trip Added: {trip_info}")
#                     else:
#                         trip_info['servicePeriod'] = service_period_str
#                         past_trips.append(trip_info)
#                         logger.debug(f"Past Trip Added: {trip_info}")
#                 else:
#                     logger.warning(f"JobPosting or service_period is missing for trip ID {trip.id}")

#             data = {
#                 'upcoming': upcoming_trips,
#                 'past': past_trips
#             }

#             logger.debug(f"Final Response Data: {data}")
#             return JsonResponse(data, status=200)

#         except jwt.ExpiredSignatureError:
#             logger.warning("Token has expired")
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             logger.warning("Invalid token")
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             logger.error("User not found")
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             logger.error(f"An error occurred: {str(e)}")
#             return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
#     else:
#         logger.warning("Invalid request method")
#         return JsonResponse({'message': 'Invalid request method'}, status=405)

from django.shortcuts import render
from django.http import JsonResponse
from .models import JobPosting, Chat, User
import jwt
from django.conf import settings

@csrf_exempt
def user_trips_view(request):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            # Fetch job postings associated with the user and exclude those with deleted chats
            trips = JobPosting.objects.filter(
                user=user,
                status='open'  # Modify the filter criteria as needed
            ).exclude(
                service_provider_requests__chats__status='deleted'
            ).distinct()

            # Serialize trips as needed
            trips_data = []
            for trip in trips:
                trips_data.append({
                    'id': trip.id,
                    'service_type': trip.service_type,
                    'service_period': trip.service_period,
                    'service_rate': trip.service_rate,
                    'onboarding_location': trip.onboarding_location,
                    'job_summary': trip.job_summary,
                    'status': trip.status,
                    'created_at': trip.created_at,
                    'updated_at': trip.updated_at,
                })

            return JsonResponse({'trips': trips_data}, status=200)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

import logging
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import JobPosting, Transaction, Hiring, User
import jwt
from django.conf import settings
from datetime import datetime
from django.utils import timezone

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@csrf_exempt
def driver_trips_view(request):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)

            logger.debug(f"Driver ID: {user_id} - {user.email} is requesting their trips")

            # Get all confirmed hirings for the driver
            confirmed_trips = Hiring.objects.filter(service_provider=user).select_related('customer', 'transaction', 'transaction__job_posting')
            logger.debug(f"Total confirmed trips: {confirmed_trips.count()}")

            upcoming_trips = []
            past_trips = []
            current_time = timezone.now().date()

            for trip in confirmed_trips:
                job_posting = trip.transaction.job_posting

                if job_posting and job_posting.service_period:
                    service_period_str = job_posting.service_period  # Example: '2024-08-17 - 2024-08-25'
                    service_period_start_str, service_period_end_str = service_period_str.split(' - ')

                    service_period_start = datetime.strptime(service_period_start_str, '%Y-%m-%d').date()
                    service_period_end = datetime.strptime(service_period_end_str, '%Y-%m-%d').date()

                    profile_photo_url = request.build_absolute_uri(settings.MEDIA_URL + trip.customer.profile_photo) if trip.customer.profile_photo else 'https://www.shutterstock.com/image-vector/vector-flat-illustration-grayscale-avatar-600nw-2281862025.jpg'

                    trip_info = {
                        'id': trip.id,
                        'customerProfilePic': profile_photo_url,
                        'customerName': f"{trip.customer.first_name} {trip.customer.last_name}",
                        'serviceProviderType': job_posting.service_type,
                        'serviceRate': trip.transaction.rate,
                        'servicePeriodStart': service_period_start_str,
                        'servicePeriodEnd': service_period_end_str,
                        'tripId': trip.id,
                        'transactionId': trip.transaction.id,
                        'jobPostingId': job_posting.id,
                    }

                    # Log trip details for debugging
                    logger.debug(f"Processing Trip: {trip_info}")

                    if service_period_end >= current_time:
                        days_to_go = (service_period_end - current_time).days
                        trip_info['daysToGo'] = days_to_go
                        upcoming_trips.append(trip_info)
                        logger.debug(f"Upcoming Trip Added: {trip_info}")
                    else:
                        trip_info['servicePeriod'] = service_period_str
                        past_trips.append(trip_info)
                        logger.debug(f"Past Trip Added: {trip_info}")
                else:
                    logger.warning(f"JobPosting or service_period is missing for trip ID {trip.id}")

            data = {
                'upcoming': upcoming_trips,
                'past': past_trips
            }

            logger.debug(f"Final Response Data: {data}")
            return JsonResponse(data, status=200)

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except User.DoesNotExist:
            logger.error("User not found")
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        logger.warning("Invalid request method")
        return JsonResponse({'message': 'Invalid request method'}, status=405)











from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Hiring
import jwt
from django.conf import settings
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@csrf_exempt
def trip_details(request, hiring_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']

            hiring = get_object_or_404(Hiring, id=hiring_id, customer_id=user_id)
            transaction = hiring.transaction
            job_posting = transaction.job_posting

            logger.debug(f"User {user_id} is viewing details for trip {hiring_id}")

            response_data = {
                'jobPosting': {
                    'serviceType': job_posting.service_type,
                    'servicePeriod': job_posting.service_period,
                    'serviceRate': job_posting.service_rate,
                    'onboardingLocation': job_posting.onboarding_location,
                    'jobSummary': job_posting.job_summary,
                },
                'transaction': {
                    'rate': transaction.rate,
                    'datetime': transaction.datetime,
                    'paymentMethod': transaction.payment_method,
                }
            }

            logger.debug(f"Response Data: {response_data}")
            return JsonResponse(response_data, status=200)

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except Hiring.DoesNotExist:
            logger.error(f"Hiring with ID {hiring_id} not found for user {user_id}")
            return JsonResponse({'message': 'Trip not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        logger.warning("Invalid request method")
        return JsonResponse({'message': 'Invalid request method'}, status=405)


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Hiring
import jwt
from django.conf import settings
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@csrf_exempt
def driver_trip_details_view(request, trip_id):
    if request.method == 'GET':
        token = request.headers.get('Authorization', '').split('Bearer ')[-1]
        try:
            # Decode the JWT token to get the user_id
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']

            # Get the Hiring object for the given trip_id where the service provider is the current user
            hiring = get_object_or_404(Hiring, id=trip_id, service_provider_id=user_id)
            transaction = hiring.transaction
            job_posting = transaction.job_posting

            logger.debug(f"Driver {user_id} is viewing details for trip {trip_id}")

            response_data = {
                'jobPosting': {
                    'serviceType': job_posting.service_type,
                    'servicePeriod': job_posting.service_period,
                    'serviceRate': str(job_posting.service_rate),
                    'onboardingLocation': job_posting.onboarding_location,
                    'jobSummary': job_posting.job_summary,
                },
                'transaction': {
                    'rate': str(transaction.rate),
                    'datetime': transaction.datetime,
                    'paymentMethod': transaction.payment_method,
                }
            }

            logger.debug(f"Response Data: {response_data}")
            return JsonResponse(response_data, status=200)

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return JsonResponse({'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except Hiring.DoesNotExist:
            logger.error(f"Hiring with ID {trip_id} not found for driver {user_id}")
            return JsonResponse({'message': 'Trip not found'}, status=404)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        logger.warning("Invalid request method")
        return JsonResponse({'message': 'Invalid request method'}, status=405)

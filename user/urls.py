from django.contrib import admin
from django.urls import include, path
from . import views
from .views import (
    get_users, get_accepted_requests, add_new_user, signup_view_customer, 
    login_view, profile_view, job_posting, get_user_job_postings, 
    get_all_job_postings, get_relevant_job_postings, SignupViewServiceProvider, 
    ServiceProviderRequestView, LoginViewServiceProvider, service_provider_profile_view, 
    RequestedJobPostingsView, get_driver_requests, request_details, delete_job_posting, 
    accept_request, reject_request, get_conversations_customer, delete_chat, 
    send_message_customer, get_messages_customer, send_message_service_provider, trip_details,
    get_messages_service_provider, trip_info, live_data_stream, user_trips_view, driver_trips_view,driver_trip_details_view,
    get_conversations_service_provider, trip_info_serviceprovider, job_postings_sse, book_trip, mark_messages_as_seen, upload_profile_photo_serviceprovider, profile_view_customer
)
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("", get_users),
    path("acceptedrequests", get_accepted_requests),
    path("adduser", add_new_user),
    path('signup/customer', signup_view_customer, name='signup'),
    path('login/customer', login_view, name='login'),
    path('profile/customer', profile_view_customer, name='profile_view'),
    path('job_posting', job_posting, name='job_posting_view'),
    path('job_postings/user', get_user_job_postings, name='get_user_job_postings'),
    path('job_postings/all', get_all_job_postings, name='get_all_job_postings'),
    path('relevant-job-postings', get_relevant_job_postings, name='get_relevant_job_postings'),
    path('signup/serviceprovider', SignupViewServiceProvider.as_view(), name='signup_serviceprovider'),
    path('service-provider-request', ServiceProviderRequestView.as_view(), name='service_provider_request'),
    path('login/serviceprovider', LoginViewServiceProvider, name='login_serviceprovider'),
    path('profile/serviceprovider', service_provider_profile_view, name='service_provider_profile_view'),
    path('requested-job-postings', RequestedJobPostingsView.as_view(), name='requested_job_postings'),
    path('driver-requests', get_driver_requests, name='get_driver_requests'),
    path('request-details/<int:request_id>/', request_details, name='request_details'),
    path('delete_job_posting/<int:job_id>/', delete_job_posting, name='delete_job_posting'),
    path('accept-request/<int:request_id>/', accept_request, name='accept_request'),
    path('reject-request/<int:request_id>/', reject_request, name='reject_request'),
    path('conversations/', get_conversations_customer, name='get_conversations_customer'),
    path('delete-chat/<int:chat_id>/', delete_chat, name='delete_chat'),
    path('send-message-customer/', send_message_customer, name='send_message_customer'),
    path('get-messages-customer/<int:chat_id>/', get_messages_customer, name='get_messages_customer'),
    path('send-message-service-provider/', send_message_service_provider, name='send_message_service_provider'),
    path('get-messages-service-provider/<int:chat_id>/', get_messages_service_provider, name='get_messages_service_provider'),
    path('trip-info/<int:chat_id>/', trip_info, name='trip_info'),
    path('sse/', live_data_stream, name='live_data_stream'),
    path('service-provider/conversations', get_conversations_service_provider, name='get_conversations_service_provider'),
    path('service-provider/trip-info/<int:chat_id>/', trip_info_serviceprovider, name='trip-info-serviceprovider'),
    path('job-postings-sse/', job_postings_sse, name='job-postings-sse'),
   
   
    path('upload-profile-photo/serviceprovider', upload_profile_photo_serviceprovider, name='upload_profile_photoS'),
    path('book-trip/<int:chat_id>/', book_trip, name='book_trip'),
    path('conversations/<int:conversation_id>/mark_seen/', mark_messages_as_seen, name='mark_messages_as_seen'),
    path('customer_trips/', user_trips_view, name='user_trips'),
    path('driver_trips/', driver_trips_view, name='driver_trips'),
    path('trip-details/<int:hiring_id>/', trip_details, name='trip_details'),
    path('driver_trip-details/<int:trip_id>/', driver_trip_details_view, name='driver_trip_details')




]



if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
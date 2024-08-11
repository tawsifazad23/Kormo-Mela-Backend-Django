from django.http import HttpResponse
import json

def user_view(request):
    data = {
        "user": "Palak",
        "phone": "+880 1711650085",
        "address": "Road 1, House 124, DOHS Baridhara, Dhaka-1206",
        "rating": "5", 
        "trips": "30",

    }


    {
            "name": "John Doe",
            "phone": "+1 1234567890",
            "address": "123 Main St, Springfield, USA",
            "rating": 4,
            "trips": 15,
    }
    json_data = json.dumps(data)
    return HttpResponse(json_data)
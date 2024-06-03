from datetime import timedelta

from config import settings

task_serializer = "json"
result_serializer = "json"
accept_content = ["json"]

broker_url = settings.CELERY_BROKER_REDIS
broker_transport_options = {"visibility_timeout": 3600 * 6}
result_backend = settings.CELERY_BROKER_REDIS
result_persistent = False

imports = ("tasks.email")


beat_schedule = {
    "fetch_packets": {
        "task": "tasks.email.process_packets",
        "schedule": timedelta(seconds=30)
    },
    "load_packets": {
        "task": "tasks.email.load_packets",
        "schedule": timedelta(seconds=20)
    },
    "delete_packets": {
        "task": "tasks.email.delete_packets",
        "schedule": timedelta(minutes=60)
    }
}





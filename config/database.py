from pymongo import MongoClient
CONNECTION_STRING = "mongodb+srv://siddharthgoyal:t2KHFCLmvshVZpN6@cluster0.fqx5j.mongodb.net/test"

client = MongoClient("mongodb+srv://siddharthgoyal:t2KHFCLmvshVZpN6@cluster0.fqx5j.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = client.todo_app


collection_name = db["todos_app"]

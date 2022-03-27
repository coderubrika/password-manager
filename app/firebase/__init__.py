import firebase_admin
from firebase_admin import auth, credentials, firestore


class FirestoreCrudService:
    def __init__(self, db):
        self.db = db
        self.collection = db.collection('User')

    def create(self, id, data):
        self.collection.document(id).set(data)

    def read(self, id):
        return self.collection.document(id).get().to_dict()

    def update(self, id, updating_data):
        pass

    def delete(self, id):
        self.collection.document(id).delete()

    def clear(self):
        [self.delete(doc.id) for doc in self.collection.get()]


credential = credentials.Certificate("config/serviceAccountKey.json")
default_app = firebase_admin.initialize_app(credential)
db_client = firestore.client()
FirestoreCrudService = FirestoreCrudService(db_client)



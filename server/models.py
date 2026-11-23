from marshmallow import Schema, fields
from sqlalchemy.ext.hybrid import hybrid_property

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    # The password hash is stored in the _password_hash column and should not be accessed directly
    _password_hash = db.Column(db.String)

    # The password property is write-only and should be set using the password_hash setter
    @hybrid_property
    def password_hash(self):
        # Raise an exception if someone tries to access the password hash directly
        raise Exception("Password hashes may not be viewed")
    
    # The password_hash setter will generate and store the hashed password
    @password_hash.setter
    def password_hash(self, password):
        # Generate the password hash using bcrypt
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        # Store the hashed password in the _password_hash column
        self._password_hash = password_hash.decode('utf-8')

    # The authenticate method checks if the provided password matches the stored hash
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()

    
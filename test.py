import auth
import unittest

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        auth.app.testing = True
        self.app = auth.app.test_client()
    
    def test_config_db(self):
        assert self.app.config['DEBUG'] is True
        assert self.app.config['SQLALCHEMY_DATABASE_URI'] == "postgresql://postgres:admin123@localhost/testtask"


    def test_get_users(self):
        result = self.app.get('/users')
        return result

    def test_register_users(self):
        result = self.app.post('/POST/register')
        return result
    
    def test_login_user(self):
     result =self.app.post('/POST/login')
     return result
    

    def test__createjob(self):
     result =self.app.post('/POST/createjob')
     return result

    def test__update_job(self):
     result =self.app.put('/PUT/job/<job_id>')
     return result

    def test__delete_job(self):
      result =self.app.delete('/DELETE/job/<job_id>')
      return result

    def test__get_jobs(self):
     result =self.app.get('/GET/jobs')
     return result

if __name__ == '__main__':
    unittest.main()







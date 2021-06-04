import boto3

client = boto3.client('cognito-idp', region_name='ap-southeast-2')

valid = False

username = "asoa"
password = "123456"
response = ""
try:
  response = client.initiate_auth(
    ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
      'USERNAME':username,
      'PASSWORD':password
    }
  )
except:
  valid = True
  print(valid)

print(response)
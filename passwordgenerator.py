import base64
import uuid
import httplib
import urlparse
import json
import boto3
import string
import random

def put_password_to_parameter_store(parameter_name, parameter_description, key_id, password):
    """
    Function to store the data to SSM
    :param parameter_name: What will be the parameter name ?
    :param parameter_description: What will be the parameter_description ?
    :param key_id: AWS KMS ID
    :param password: password, will be saved to SSM
    """
    client = boto3.client('ssm')
    response = client.put_parameter(
        Name=parameter_name,
        Description=parameter_description,
        Value=password,
        Type='SecureString',
        KeyId=key_id,
        Overwrite=True
    )

    return response

def get_password_from_parameter_store(parameter_name, key_id):
    """
    Function to get the encrypted data from the SSM
    :param parameter_name: What will be the parameter name ?
    :param key_id: AWS KMS ID
    """
    client = boto3.client('ssm')
    response = client.get_parameters(
        Names=[
            parameter_name,
        ],
        WithDecryption=True
    )

    credentials = response['Parameters'][0]['Value']

    return credentials


def generate_random_password(password_length=20):
    """
    Generates a random password sent back to CF
    :param password_length: Length of the password in number of characters
    :return: String of the password
    """
    password = ''
    char_set = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-'
    while '-' not in password:
        password = ''.join(random.sample(char_set * 6, int(password_length)))
    return password

def send_response(request, response, status=None, reason=None):
    """
    Send our response to the pre-signed URL supplied by CloudFormation
    If no ResponseURL is found in the request, there is no place to send a
    response. This may be the case if the supplied event was for testing.
    :return: response object
    """

    if status is not None:
        response['Status'] = status

    if reason is not None:
        response['Reason'] = reason

    if 'ResponseURL' in request and request['ResponseURL']:
        try:
            url = urlparse.urlparse(request['ResponseURL'])
            body = json.dumps(response)
            https = httplib.HTTPSConnection(url.hostname)
            https.request('PUT', url.path + '?' + url.query, body)
        except:
            print("Failed to send the response to the provdided URL")
    return response

def lambda_handler(event, context):
    """
    Core function called by Lambda
    The function will determine what to do when called.
    :param event: Lambda event data
    :param context: Lambda defined context params
    :return: Calls for send_response when the code could be executed without problem
    """

    response = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'SUCCESS'
        'Data': ''
    }

    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = str(uuid.uuid4())

    if event['ResourceProperties']['Type'] == 'encrypt':

        db_password = generate_random_password(event['ResourceProperties']['PasswordLength'])
        put_password_to_parameter_store(
                                 event['ResourceProperties']['ParameterName'],
                                 event['ResourceProperties']['ParameterDescription'],
                                 event['ResourceProperties']['KeyId'],
                                 db_password
                                 )
    else:
        response['Data']['Password'] = get_password_from_parameter_store(
                                event['ResourceProperties']['ParameterName'],
                                event['ResourceProperties']['KeyId'],
                                )

    response['Reason'] = 'The value was successfully encrypted'
    return send_response(event, response)

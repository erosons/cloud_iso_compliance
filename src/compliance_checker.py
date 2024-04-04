# Import necessary AWS SDK and other libraries
import boto3
from botocore.exceptions import ClientError

# Define the structure for storing compliance check results
compliance_results = []


def check_iam_minimum_password_length():
    """
    Check IAM password policy for minimum password length compliance.
    """
    try:
        # Initialize IAM client
        iam = boto3.client('iam')
        
        # Retrieve the account password policy
        response = iam.get_account_password_policy()
        policy = response['PasswordPolicy']
        
        # Check for minimum password length of 12 characters
        if policy['MinimumPasswordLength'] < 12:
            compliance_results.append({
                'check': 'IAM Minimum Password Length',
                'status': 'FAIL',
                'details': 'Password length is less than 12 characters.'
            })
        else:
            compliance_results.append({
                'check': 'IAM Minimum Password Length',
                'status': 'PASS',
                'details': 'Compliant with minimum password length of 12 characters.'
            })
    except ClientError as e:
        compliance_results.append({
            'check': 'IAM Minimum Password Length',
            'status': 'ERROR',
            'details': str(e)
        })

# Example call to the compliance check function
check_iam_minimum_password_length()

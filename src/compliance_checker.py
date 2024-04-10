import boto3
from botocore.exceptions import ClientError

# Define the structure for storing compliance check results
compliance_results = []

def check_iam_minimum_password_length():
    """
    Check IAM password policy for minimum password length compliance.
    """
    try:
        iam = boto3.client('iam')
        response = iam.get_account_password_policy()
        policy = response['PasswordPolicy']
        
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

def check_user_registration_deregistration():
    """
    This function checks for the presence of a process or policy for user registration and de-registration.
    """
    # This is more of a procedural check and might not be directly verifiable via a script.
    # You should ensure there are mechanisms or procedures in place to manage this.
    compliance_results.append({
        'check': 'User Registration and De-registration',
        'status': 'REVIEW',
        'details': 'Manual review required to ensure procedures for user management align with ISO 27001.'
    })

def check_privileged_access_management():
    """
    Check for the management and review of privileged access rights.
    """
    # Similar to user registration, direct verification might require manual review of policies and practices.
    compliance_results.append({
        'check': 'Management of Privileged Access Rights',
        'status': 'REVIEW',
        'details': 'Manual review required to ensure privileged access is appropriately managed.'
    })

def check_mfa_for_privileged_users():
    """
    Check if MFA is enabled for privileged IAM users.
    """
    try:
        iam = boto3.client('iam')
        users = iam.list_users()['Users']
        mfa_not_enabled = []
        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                mfa_not_enabled.append(user['UserName'])
        
        if mfa_not_enabled:
            compliance_results.append({
                'check': 'MFA for Privileged Users',
                'status': 'FAIL',
                'details': f'MFA not enabled for privileged users: {", ".join(mfa_not_enabled)}'
            })
        else:
            compliance_results.append({
                'check': 'MFA for Privileged Users',
                'status': 'PASS',
                'details': 'All privileged users have MFA enabled.'
            })
    except ClientError as e:
        compliance_results.append({
            'check': 'MFA for Privileged Users',
            'status': 'ERROR',
            'details': str(e)
        })

# Run the compliance check functions
check_iam_minimum_password_length()
check_user_registration_deregistration()
check_privileged_access_management()
check_mfa_for_privileged_users()

# Example of how to print the results
for result in compliance_results:
    print(result)

from srht.crypto import internal_anon
from srht.graphql import exec_gql

def send_email(address, msg):
    email_mutation = """
    mutation SendEmail($address: String!, $msg: String!) {
        sendEmail(address: $address, message: $msg)
    }
    """
    r = exec_gql("meta.sr.ht", email_mutation, user=internal_anon,
        address=address, msg=msg)

from srht.crypto import internal_anon
from srht.graphql import exec_gql

def send_email_notification(username, msg):
    email_mutation = """
    mutation SendEmail($username: String!, $msg: String!) {
        sendEmailNotification(username: $username, message: $msg)
    }
    """
    r = exec_gql("meta.sr.ht", email_mutation, user=internal_anon,
        username=username, msg=msg)

def send_email_external(address, msg):
    email_mutation = """
    mutation SendEmailExt($address: String!, $msg: String!) {
        sendEmailExternal(address: $address, message: $msg)
    }
    """
    r = exec_gql("meta.sr.ht", email_mutation, user=internal_anon,
        address=address, msg=msg)

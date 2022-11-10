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

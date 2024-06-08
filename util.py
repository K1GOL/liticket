import hashlib

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password, salt, 2^20).hex()

def parse_field(field):
  return {
    'id': field[0],
    'name': field[1],
    'description': field[2],
    'required': field[3] == 1,
    'enum': field[4] == 1,
  }

def parse_fields(fields):
  return [parse_field(field) for field in fields]

def parse_queue(queue):
  return {
    'id': queue[0],
    'name': queue[1],
    'description': queue[2]
  }

def parse_queues(queues):
  return [parse_queue(queue) for queue in queues]

def parse_status(status):
  return {
    'id': status[0],
    'name': status[1],
    'description': status[2],
    'color': status[3]
  }

def parse_statuses(statuses):
  return [parse_status(status) for status in statuses]

def parse_field_option(option):
  return {
    'field': option[0],
    'value': option[1]
  }

def parse_field_options(options):
  return [parse_field_option(option) for option in options]

def parse_ticket(ticket):
  return {
    'id': ticket[0],
    'title': ticket[1],
    'description': ticket[2],
    'queue': ticket[3],
    'owner': ticket[4],
    'created_at': ticket[5],
    'updated_at': ticket[6],
    'status': ticket[7],
  }

def parse_tickets(tickets):
  return [parse_ticket(ticket) for ticket in tickets]

def parse_field_value(value):
  return {
    'field': value[0],
    'ticket': value[1],
    'value': value[2]
  }

def parse_field_values(values):
  return [parse_field_value(value) for value in values]

def parse_user(user):
  return {
    'id': user[0],
    'username': user[1],
    'display_name': user[3]
  }

def parse_users(users):
  return [parse_user(user) for user in users]

def parse_comment(comment):
  return {
    'id': comment[0],
    'content': comment[1],
    'created_at': comment[2],
    'author': comment[3],
    'ticket': comment[4]
  }

def parse_comments(comments):
  return [parse_comment(comment) for comment in comments]

def parse_attachment(attachment):
  return {
    'id': attachment[0],
    'ticket': attachment[1],
    'name': attachment[2],
    'mime_type': attachment[3],
    'content': attachment[4]
  }

def parse_attachments(attachments):
  return [parse_attachment(attachment) for attachment in attachments]

def parse_saved_query(saved_query):
  return {
    'id': saved_query[0],
    'name': saved_query[1],
    'query': saved_query[2],
    'user': saved_query[3]
  }

def parse_saved_queries(saved_queries):
  return [parse_saved_query(saved_query) for saved_query in saved_queries]

def parse_history(item):
  return {
    'id': item[0],
    'ticket': item[1],
    'created_at': item[2],
    'author': item[3],
    'field': item[4],
    'old_value': item[5],
    'new_value': item[6]
  }

def parse_history_changes(changes):
  return [parse_history(change) for change in changes]
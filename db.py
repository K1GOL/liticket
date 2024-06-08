import sqlite3
import threading
import time
from util import hash_password
import os

class SQLiteDatabase:
    # This class is a wrapper around the SQLite database.
    # It provides an interface to add, update, and delete data from the database.
    def __init__(self):
        self.lock = threading.Lock()
        db_name = "liticket.db"
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()

        # Functions for locking and unlocking the database.
        def gl():
            self.lock.acquire()

        def rl():
            self.lock.release()

        self.getlock = gl
        self.rellock = rl

        self.init_tables()

        # Check if there are any users in the database
        self.cursor.execute("SELECT * FROM Users")
        users = self.cursor.fetchall()

        # If there are no users in the database, create a default user
        if len(users) == 0:
            salt = os.urandom(32)
            pwd = hash_password("admin".encode(), salt)
            self.add_user("default_admin",  "default_admin", "Default administrator", pwd, True, salt.hex())
        
    def init_tables(self):
        self.getlock()
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Users (id TEXT PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, display_name TEXT NOT NULL, admin INTEGER, salt TEXT NOT NULL, UNIQUE(username))"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketQueues (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketStatuses (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, color TEXT, UNIQUE(name))"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketFieldTypes (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, required INTEGER, enum INTEGER, UNIQUE(name))"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketFieldOptions (field TEXT, value TEXT, PRIMARY KEY(field, value), FOREIGN KEY(field) REFERENCES TicketFieldTypes(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketFieldValues (field TEXT, ticket TEXT, value TEXT, PRIMARY KEY(field, ticket), FOREIGN KEY(field) REFERENCES TicketFieldTypes(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY(ticket) REFERENCES Tickets(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Tickets (id TEXT PRIMARY KEY, title TEXT, description TEXT, queue TEXT NOT NULL, owner TEXT, created_at TEXT, updated_at TEXT, status TEXT, FOREIGN KEY(queue) REFERENCES TicketQueues(id) ON UPDATE CASCADE ON DELETE SET NULL, FOREIGN KEY(owner) REFERENCES Users(id) ON UPDATE CASCADE ON DELETE SET NULL, FOREIGN KEY(status) REFERENCES TicketStatuses(id) ON UPDATE CASCADE ON DELETE SET NULL)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketComments (id TEXT PRIMARY KEY, content TEXT, created_at TEXT, author TEXT, ticket TEXT, FOREIGN KEY(ticket) REFERENCES Tickets(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY(author) REFERENCES Users(id) ON UPDATE CASCADE ON DELETE SET NULL)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketAttachments (id TEXT PRIMARY KEY, ticket TEXT NOT NULL, name TEXT, mime_type TEXT, content BLOB, FOREIGN KEY(ticket) REFERENCES Tickets(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketHistoryEntries (id TEXT PRIMARY KEY, ticket TEXT NOT NULL, created_at TEXT, author TEXT, FOREIGN KEY(ticket) REFERENCES Tickets(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY(author) REFERENCES Users(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TicketHistoryChanges (id TEXT, field TEXT, old_value TEXT, new_value TEXT, PRIMARY KEY(id, field), FOREIGN KEY(id) REFERENCES TicketHistoryEntries(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS SavedSearches (id TEXT PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL, user TEXT, FOREIGN KEY(user) REFERENCES Users(id) ON UPDATE CASCADE ON DELETE CASCADE)"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS UserDashboards (user TEXT, saved_search TEXT, position INTEGER NOT NULL, PRIMARY KEY(user, saved_search), FOREIGN KEY(user) REFERENCES Users(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY(saved_search) REFERENCES SavedSearches(id) ON UPDATE CASCADE ON DELETE CASCADE CHECK(position > -1))"
        )
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Counter (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)"
        )
        self.conn.commit()
        self.cursor.execute(
            "INSERT OR IGNORE INTO Counter (name, value) VALUES ('tickets', 0)"
        )
        self.conn.commit()
        self.rellock()

    def add_user(self, userId, username, display_name, password, admin, salt):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO Users (id, username, password, display_name, admin, salt) VALUES (?, ?, ?, ?, ?, ?)",
            (userId, username, password, display_name, admin, salt),
        )
        self.conn.commit()
        self.rellock()

    def change_password(self, userId, password, salt):
        self.getlock()
        self.cursor.execute(
            "UPDATE Users SET password = ?, salt = ? WHERE id = ?",
            (password, salt, userId),
        )
        self.conn.commit()
        self.rellock()

    def delete_user(self, userId):
        self.getlock()
        self.cursor.execute("DELETE FROM Users WHERE id = ?", (userId,))
        self.conn.commit()
        self.rellock()

    def add_queue(self, queue):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketQueues (id, name, description) VALUES (?, ?, ?)",
            (queue['id'], queue['name'], queue['description']),
        )
        self.conn.commit()
        self.rellock()

    def add_status(self, status):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketStatuses (id, name, description, color) VALUES (?, ?, ?, ?)",
            (status['id'], status['name'], status['description'], status['color']),
        )
        self.conn.commit()
        self.rellock()

    def add_field_type(self, field_type):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketFieldTypes (id, name, description, required, enum) VALUES (?, ?, ?, ?, ?)",
            (field_type['id'], field_type['name'], field_type['description'], 1 if field_type['required'] else 0, 1 if field_type['enum'] else 0),
        )
        self.conn.commit()
        self.rellock()

    def create_ticket(self, ticket):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO Tickets (id, title, description, queue, owner, created_at, updated_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket['id'], ticket['title'], ticket['description'], ticket['queue'], ticket['owner'], ticket['created_at'], ticket['updated_at'], ticket['status']),
        )
        for field, value in ticket['fields'].items():
            self.cursor.execute(
                "INSERT INTO TicketFieldValues (field, ticket, value) VALUES (?, ?, ?)",(field, ticket['id'], value),
            )
        self.conn.commit()
        self.rellock()

    def add_comment(self, comment):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketComments (id, content, created_at, author, ticket) VALUES (?, ?, ?, ?, ?)",
            (comment['id'], comment['content'], comment['created_at'], comment['author'], comment['ticket']),
        )
        self.conn.commit()
        self.rellock()

    def add_attachment(self, attachment):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketAttachments (id, ticket, name, mime_type, content) VALUES (?, ?, ?, ?, ?)",
            (attachment['id'], attachment['ticket'], attachment['name'], attachment['mime_type'], attachment['content']),
        )
        self.conn.commit()
        self.rellock()

    def get_user_by_id(self, user_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM Users WHERE id = ?", (user_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_user_by_username(self, username: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_all_users(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM Users")
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_queues(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketQueues")
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_statuses(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketStatuses")
        result = self.cursor.fetchall()
        self.rellock()
        return result

    def get_field_types(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketFieldTypes")
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_field_by_id(self, field_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketFieldTypes WHERE id = ?", (field_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_all_field_options(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketFieldOptions")
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def add_field_option(self, field, option: str):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketFieldOptions (field, value) VALUES (?, ?)", (field['id'], option)
        )
        self.conn.commit()
        self.rellock()

    def get_ticket(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM Tickets WHERE id = ?", (ticket_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result

    def get_comments(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketComments WHERE ticket = ? ORDER BY created_at DESC", (ticket_id,))
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_comment(self, comment_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketComments WHERE id = ?", (comment_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def delete_comment(self, comment_id: str):
        self.getlock()
        self.cursor.execute("DELETE FROM TicketComments WHERE id = ?", (comment_id,))

    def get_attachments(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketAttachments WHERE ticket = ?", (ticket_id,))
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_attachment(self, attachment_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketAttachments WHERE id = ?", (attachment_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_ticket_history(self, ticket):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketHistoryEntries NATURAL JOIN TicketHistoryChanges WHERE ticket = ? ORDER BY created_at DESC", (ticket['id'],))
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def append_ticket_history(self, history):
        self.getlock()
        self.cursor.execute(
            "INSERT INTO TicketHistoryEntries (id, ticket, created_at, author) VALUES (?, ?, ?, ?)",
            (history['id'], history['ticket'], history['timestamp'], history['author'])
        )

        for change in history['changes']:
            self.cursor.execute(
                "INSERT INTO TicketHistoryChanges (id, field, old_value, new_value) VALUES (?, ?, ?, ?)",
                (history['id'], change['field'], change['old_value'], change['new_value'])
            )
        self.conn.commit()
        self.rellock()

    def get_saved_queries(self, userId: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM SavedSearches WHERE user = ?", (userId,))
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def get_public_queries(self):
        self.getlock()
        self.cursor.execute("SELECT * FROM SavedSearches WHERE user IS NULL")
        result = self.cursor.fetchall()
        self.rellock()
        return result
    
    def search_tickets(self, query: str):
        self.getlock()
        self.cursor.execute(f"SELECT * FROM Tickets WHERE {query}")
        result = self.cursor.fetchall()
        self.rellock()
        return result

    def is_admin(self, user_id: str):
        self.getlock()
        self.cursor.execute("SELECT admin FROM Users WHERE id = ?", (user_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result == (1,)
    
    def delete_queue(self, queue_id: str):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM TicketQueues WHERE id = ?", (queue_id,))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def delete_status(self, status_id: str):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM TicketStatuses WHERE id = ?", (status_id,))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def delete_field_option(self, field_id, option):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM TicketFieldOptions WHERE field = ? AND value = ?", (field_id, option))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def delete_ticket(self, ticket_id: str):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM Tickets WHERE id = ?", (ticket_id,))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def delete_comment(self, comment_id: str):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM TicketComments WHERE id = ?", (comment_id,))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def delete_attachment(self, attachment_id: str):
        self.getlock()
        try:
            self.cursor.execute("DELETE FROM TicketAttachments WHERE id = ?", (attachment_id,))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def get_ticket_field_value(self, ticket_id: str, field_id: str):
        self.getlock()
        self.cursor.execute("SELECT value FROM TicketFieldValues WHERE ticket = ? AND field = ?", (ticket_id, field_id))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_all_ticket_field_values(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM TicketFieldValues WHERE ticket = ?", (ticket_id,))
        result = self.cursor.fetchall()
        self.rellock()
        return result

    def update_ticket_updated_at(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET updated_at = ? WHERE id = ?", (round(time.time()), ticket_id))
        self.conn.commit()
        self.rellock()

    def update_ticket_status(self, ticket_id: str, status_id: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET status = ? WHERE id = ?", (status_id, ticket_id))
        self.conn.commit()
        self.rellock()

    def update_ticket_queue(self, ticket_id: str, queue_id: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET queue = ? WHERE id = ?", (queue_id, ticket_id))
        self.conn.commit()
        self.rellock()

    def update_ticket_owner(self, ticket_id: str, user_id: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET owner = ? WHERE id = ?", (user_id, ticket_id))
        self.conn.commit()
        self.rellock()

    def update_ticket_description(self, ticket_id: str, description: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET description = ? WHERE id = ?", (description, ticket_id))
        self.conn.commit()
        self.rellock()
    
    def update_ticket_title(self, ticket_id: str, title: str):
        self.getlock()
        self.cursor.execute("UPDATE Tickets SET title = ? WHERE id = ?", (title, ticket_id))
        self.conn.commit()
        self.rellock()

    def update_ticket_field_value(self, ticket_id: str, field_id: str, value: str):
        self.getlock()
        self.cursor.execute("UPDATE TicketFieldValues SET value = ? WHERE ticket = ? AND field = ?", (value, ticket_id, field_id))
        self.conn.commit()
        self.rellock()

    def delete_ticket(self, ticket_id: str):
        self.getlock()
        self.cursor.execute("DELETE FROM Tickets WHERE id = ?", (ticket_id,))
        self.conn.commit()
        self.rellock()

    def get_dashboard_queries(self, userId: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM UserDashboards WHERE user = ? ORDER BY position", (userId,))
        result = self.cursor.fetchall()
        self.rellock()
        return result

    def add_dashboard_query(self, userId: str, query: str, position: int):
        self.getlock()
        try:
            self.cursor.execute("INSERT INTO UserDashboards (user, saved_search, position) VALUES (?, ?, ?)", (userId, query, position))
            self.conn.commit()
        except Exception as e:
            print(e)
        finally:
            self.rellock()

    def get_query(self, query_id: str):
        self.getlock()
        self.cursor.execute("SELECT * FROM SavedSearches WHERE id = ?", (query_id,))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def get_dashboard_query_position(self, userId: str, query_id: str):
        self.getlock()
        self.cursor.execute("SELECT position FROM UserDashboards WHERE user = ? AND saved_search = ?", (userId, query_id))
        result = self.cursor.fetchone()
        self.rellock()
        return result
    
    def move_dashboard_query_up(self, userId: str, query_id: str):
        try:
            position = self.get_dashboard_query_position(userId, query_id)[0]
            self.getlock()
            self.cursor.execute("UPDATE UserDashboards SET position = position + 1 WHERE user = ? AND position = ?", (userId, position - 1))
            self.cursor.execute("UPDATE UserDashboards SET position = position - 1 WHERE user = ? AND saved_search = ?", (userId, query_id))
            self.conn.commit()
            self.rellock()
        except Exception as e:
            print(e)
            self.rellock()

    def move_dashboard_query_down(self, userId: str, query_id: str):
        try:
            position = self.get_dashboard_query_position(userId, query_id)[0]
            self.getlock()
            self.cursor.execute("UPDATE UserDashboards SET position = position - 1 WHERE user = ? AND position = ?", (userId, position + 1))
            self.cursor.execute("UPDATE UserDashboards SET position = position + 1 WHERE user = ? AND saved_search = ?", (userId, query_id))
            self.conn.commit()
            self.rellock()
        except Exception as e:
            print(e)
            self.rellock()

    def delete_dashboard_query(self, userId: str, query_id: str):
        self.getlock()
        self.cursor.execute("DELETE FROM UserDashboards WHERE user = ? AND saved_search = ?", (userId, query_id))
        self.conn.commit()
        self.rellock()

    def add_saved_search(self, id: str, query: str, name: str, userId: str):
        self.getlock()
        self.cursor.execute("INSERT INTO SavedSearches (id, name, query, user) VALUES (?, ?, ?, ?)", (id, name, query, userId))
        self.conn.commit()
        self.rellock()

    def next_ticket_id(self):
        self.getlock()
        self.cursor.execute("SELECT value FROM Counter WHERE name = 'tickets'")
        result = str(self.cursor.fetchone()[0])
        self.cursor.execute("UPDATE Counter SET value = value + 1 WHERE name = 'tickets'")
        self.rellock()
        return result

    def close(self):
        self.conn.close()

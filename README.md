# Liticket

Liticket is a ticketing system designed to be easy to use and lightweight. It is built using Flask, Jinja, and SQLite.

## Installation

### Production

Download the repo and run it with, for example, Waitress:
```
$ pip install waitress
$ waitress-serve --call 'Liticket:create_app'
```

### Development

Clone the repo and use `$ flask run`.

## User manual

By default, if no users exist in the database, the default admin user will be created. The username is `default_admin` and the password is `admin`.

Admin users have access to the admin panel, and can create and delete custom fields, queues, etc. They can also create and delete users, and change any users password.

The search-bar searches for the given string in the ticket description and title.

When creating new saved queries, the name is required to be unique and the query should form a valid SQL query. A private query can only be accessed by the user who created it. For example to return all tickets that have a status of `open`, use the query: `status = 'open'`. This will be inserted into the SQL query:
```SQL
SELECT *
FROM Tickets
WHERE status = 'open'
```
SQL-injection is a feature, not a bug. Deploy carefully.

## Q&A

> Why doesn't the admin panel have functionality to edit value X?

Maybe that will be added some day. Use an SQL-editor to edit the database directly.

## License

BSD-2-Clause

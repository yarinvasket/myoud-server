get_user = "select * from users where username=:username"
get_user_by_pk = "select * from users where pk=:pk"
register_user = "insert into users values (?, ?, ?, ?, ?, ?)"
create_dir = '''create table %s (
            name          text primary key,
            content       blob,
            date          integer,
            key           text,
            isfolder      integer,
            pathsig       text,
            filesig       text)'''

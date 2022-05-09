get_user = "select * from users where username=:username"
get_user_by_pk = "select * from users where pk=:pk"
register_user = "insert into users values (?, ?, ?, ?, ?, json('[]'))"

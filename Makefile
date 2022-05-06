start : database.db
	export FLASK_ENV=development
	pipenv run flask run

database.db :
	pipenv run python setup.py
